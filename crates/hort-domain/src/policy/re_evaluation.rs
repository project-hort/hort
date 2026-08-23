//! Re-evaluation decision point.
//!
//! Pure helper that decides what state a previously
//! `Rejected` artifact should land in when its verdict is recomputed
//! over stored findings under a resolved policy + exclusion set —
//! whichever caller drives the recompute (an exclusion/policy change
//! walking the loosen direction of the population pass, or a curator
//! explicitly invoking a single-artifact re-evaluation). Composition:
//! re-runs [`crate::policy::evaluate_scan_result`]'s constituent CVE
//! evaluator with the updated exclusion set and translates the result
//! into a [`ReEvaluationOutcome`] that honours quarantine invariant 3
//! (the time hold is preserved on a clean re-evaluation).
//!
//! ## Enforcement mode
//!
//! A blocking verdict holds the artifact only under
//! [`ScanEnforcement::Reject`]. Under [`ScanEnforcement::Record`] the same
//! verdict is recorded but never enforced, so a policy loosened
//! `reject → record` clears a previously-scan-rejected artifact here
//! (release authority #5, exactly as adding an exclusion does). The
//! enforcement check is applied to the SAME `action` the CVE + negligible
//! evaluators produce, so this decision point and
//! [`crate::policy::evaluate_scan_result`] cannot disagree about which
//! verdicts block.
//!
//! Pure domain — zero I/O, zero `tracing`. The application caller is
//! responsible for loading the artifact's last `ScanCompleted` summary,
//! the resolved policy + exclusion set, and translating the outcome
//! into committed events.
//!
//! ## Time-hold boundary semantics (quarantine invariant 3)
//!
//! The boundary is evaluated against the **computed** quarantine
//! deadline (`quarantine_window_start + duration`, ADR 0007), which
//! the application caller resolves via
//! [`crate::policy::effective_quarantine_deadline`] and passes in as
//! `quarantine_deadline` — **never** the bare stored anchor. The anchor
//! is always in the past, so passing it here would always read
//! "elapsed" and release a re-evaluated `rejected` artifact ~`duration`
//! early.
//!
//! `quarantine_deadline <= now` returns [`ReEvaluationOutcome::ResetToReleased`]:
//! the time hold has elapsed, so the artifact moves directly to released.
//! `quarantine_deadline > now` returns [`ReEvaluationOutcome::ResetToQuarantined`]:
//! the remaining observation window still applies, so the artifact returns
//! to quarantined and waits out the timer.
//!
//! Equality at the boundary (`quarantine_deadline == now`) is treated as
//! "elapsed" — the `<=` comparison favours
//! [`ReEvaluationOutcome::ResetToReleased`]. The wall-clock at apply time
//! is monotonic only at one-second resolution; either choice is
//! defensible; the chosen framing ("if the deadline is still in the
//! future") makes "future" the discriminator and "now" the complement.

use chrono::{DateTime, Utc};

use crate::entities::artifact::Artifact;
use crate::entities::scan_policy::{ExclusionProjection, ScanEnforcement, ScanPolicyProjection};
use crate::events::SeveritySummary;
use crate::types::{ArtifactCoords, Finding};

use super::cve::evaluate_cve_thresholds;
use super::exclusion::{filter_excluded_findings, filter_excluded_summary};
use super::primitives::{PolicyAction, ViolationsAccumulator};
use super::scan::{collect_negligible_action, DefaultPolicy};

/// Outcome of [`decide_rejected_transition`].
///
/// `StillRejected` means the new exclusion did not clear all blocking
/// findings — the artifact remains `Rejected`. `ResetToQuarantined` and
/// `ResetToReleased` are both "clean" outcomes; the caller chooses
/// between them based on whether the time hold has elapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReEvaluationOutcome {
    /// Re-evaluation under the updated exclusion set still rejects.
    StillRejected,
    /// Scan now passes; the time-based observation window is still
    /// active so the artifact returns to `Quarantined`.
    ResetToQuarantined,
    /// Scan now passes; the time-based observation window has elapsed
    /// (or was never set) so the artifact moves directly to `Released`.
    ResetToReleased,
}

/// Decides what state a previously `Rejected` artifact transitions to
/// when its verdict is recomputed over stored findings under the
/// resolved policy + exclusion set.
///
/// Composes a CVE evaluator with the time-hold boundary check. The CVE
/// evaluator runs in one of two modes:
///
/// 1. **Per-finding mode** — when `last_findings`
///    is `Some(&[Finding])`, [`filter_excluded_findings`] performs
///    exact CVE-ID matching against each finding and the post-filter
///    `SeveritySummary` is computed from the survivors. One exclusion
///    drops every finding it matches, matching the operator mental
///    model captured in `crates/hort-domain/src/policy/exclusion.rs`'s
///    `cve_matches` rule.
///
/// 2. **Aggregate-summary fallback** — when
///    `last_findings` is `None`, [`filter_excluded_summary`] applies
///    the highest-tier-first decrement: each active+pattern-matching
///    exclusion decrements one count from the highest non-zero tier
///    (Critical → High → Medium → Low). Preserved bit-for-bit
///    for callers that cannot resolve the `findings_blob`
///    (clean scans, missing CAS object, deserialise failure).
///
/// The caller has already loaded the artifact's last `ScanCompleted`
/// summary (`last_scan_summary`), the resolved active scan policy
/// (`policy`), the *updated* exclusion list including the
/// just-added exclusion (`updated_exclusions`), and optionally the
/// per-finding rows hydrated from CAS (`last_findings`).
///
/// `quarantine_deadline` is the artifact's **computed** quarantine
/// window deadline (`quarantine_window_start + duration`, ADR 0007)
/// — passed in explicitly so the domain layer remains time-source-free
/// (`Utc::now()` is forbidden inside `hort-domain`) and policy-free (the
/// duration is resolved by the application caller via
/// [`crate::policy::effective_quarantine_deadline`]). **Pass the
/// computed deadline, never the bare `quarantine_window_start` anchor**
/// — both are `Option<DateTime<Utc>>`, so the anchor type-checks but
/// releases re-evaluated `rejected` artifacts ~`duration` early.
/// `None` means no quarantine hold applies; treated as "elapsed"
/// for the purposes of the boundary check.
///
/// `now` is the current wall-clock; passed in by the caller for the
/// same reason.
///
/// See module rustdoc for the boundary semantics
/// (`quarantine_deadline <= now` favours `ResetToReleased`).
pub fn decide_rejected_transition(
    artifact: &Artifact,
    last_scan_summary: &SeveritySummary,
    last_findings: Option<&[Finding]>,
    policy: Option<&ScanPolicyProjection>,
    updated_exclusions: &[ExclusionProjection],
    quarantine_deadline: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> ReEvaluationOutcome {
    let coords = ArtifactCoords {
        name: artifact.name.clone(),
        name_as_published: artifact.name_as_published.clone(),
        version: artifact.version.clone(),
        path: artifact.path.clone(),
        // Format is required by `coords` but not consulted by the
        // exclusion filter's `package_pattern` matcher (which uses
        // `coords.name`). Use a sentinel — the domain layer must not
        // reach across to the repository repository to resolve the
        // real format here, and the evaluator does not need it.
        format: crate::entities::repository::RepositoryFormat::Other(String::new()),
        metadata: serde_json::Value::Null,
    };

    // Prefer per-finding matching when the caller
    // hydrated the findings_blob from CAS. Falls back to the
    // aggregate-summary path when `last_findings` is `None` (clean
    // scan, missing CAS object, or deserialise failure — the helper
    // `read_last_findings` already logged a warn for the corruption
    // cases).
    let post_exclusion_summary = match last_findings {
        Some(findings) => {
            filter_excluded_findings(findings, updated_exclusions, &coords, now).remaining
        }
        None => {
            filter_excluded_summary(last_scan_summary, updated_exclusions, &coords, now).remaining
        }
    };
    let threshold = policy
        .map(|p| p.severity_threshold)
        .unwrap_or_else(DefaultPolicy::block_on_critical);
    let mut accumulator = ViolationsAccumulator::new();
    accumulator.collect_with_severity_escalation(evaluate_cve_thresholds(
        &post_exclusion_summary,
        threshold,
    ));
    // Mirror the initial scan's Step 4b: a `negligible_action: Block`
    // rejection must survive an exclusion-triggered re-evaluation. The
    // shared helper is the single source of this decision, so this path
    // cannot silently drop a Block that `evaluate_scan_result` enforces.
    let negligible_action = policy
        .map(|p| p.negligible_action)
        .unwrap_or_else(DefaultPolicy::negligible_action);
    collect_negligible_action(
        &mut accumulator,
        negligible_action,
        post_exclusion_summary.negligible,
    );
    let (action, _violations) = accumulator.into_outcome();

    // Mirror the initial scan's Step 5: the resolved `enforcement`
    // decides whether a blocking verdict may hold the artifact at all.
    // Under `record` a `Block` is recorded, never enforced — so a policy
    // loosened `reject → record` clears the rejection here, exactly as an
    // exclusion that drops the last blocking finding does, and the
    // artifact leaves `Rejected` through release authority #5. The two
    // enforcement branches share the same computed `action`, so the
    // loosen and tighten directions cannot disagree about the verdict.
    let enforcement = policy
        .map(|p| p.enforcement)
        .unwrap_or_else(DefaultPolicy::enforcement);
    let blocks =
        matches!(action, PolicyAction::Block) && matches!(enforcement, ScanEnforcement::Reject);
    if blocks {
        return ReEvaluationOutcome::StillRejected;
    }
    match quarantine_deadline {
        Some(deadline) if deadline > now => ReEvaluationOutcome::ResetToQuarantined,
        // `deadline <= now` OR `None` — time hold elapsed or never set.
        _ => ReEvaluationOutcome::ResetToReleased,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::artifact::QuarantineStatus;
    use crate::entities::repository::RepositoryFormat;
    use crate::entities::scan_policy::{NegligibleAction, ProvenanceMode, SeverityThreshold};
    use crate::events::PolicyScope;
    use crate::types::{ContentHash, Finding};
    use chrono::TimeZone;
    use uuid::Uuid;

    const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0)
            .single()
            .expect("fixed timestamp")
    }

    fn rejected_artifact(name: &str) -> Artifact {
        Artifact {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            name: name.into(),
            name_as_published: name.into(),
            version: Some("1.0.0".into()),
            path: format!("/{name}/1.0.0"),
            size_bytes: 1,
            sha256_checksum: VALID_SHA256.parse::<ContentHash>().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: QuarantineStatus::Rejected,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            created_at: ts(0),
            updated_at: ts(0),
        }
    }

    fn summary(critical: u32, high: u32, medium: u32, low: u32) -> SeveritySummary {
        SeveritySummary {
            critical,
            high,
            medium,
            low,
            negligible: 0,
        }
    }

    fn projection(threshold: SeverityThreshold) -> ScanPolicyProjection {
        ScanPolicyProjection {
            policy_id: Uuid::from_u128(0xa11ce),
            name: "test-policy".into(),
            scope: PolicyScope::Global,
            severity_threshold: threshold,
            quarantine_duration_secs: 0,
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            stream_version: 0,
            created_at: ts(0),
            updated_at: ts(0),
        }
    }

    fn exclusion(cve_id: &str) -> ExclusionProjection {
        ExclusionProjection {
            exclusion_id: Uuid::from_u128(1),
            policy_id: Uuid::from_u128(0xa11ce),
            cve_id: cve_id.into(),
            package_pattern: None,
            scope: PolicyScope::Global,
            reason: "patched".into(),
            added_by_actor_id: None,
            expires_at: None,
        }
    }

    // -- StillRejected ------------------------------------------------------

    #[test]
    fn still_rejected_when_critical_unmasked_by_exclusion() {
        // Two critical findings, only one exclusion — one finding still
        // blocks under default threshold (aggregate-summary fallback
        // path).
        let artifact = rejected_artifact("xz-utils");
        let summary = summary(2, 0, 0, 0);
        let exclusions = vec![exclusion("CVE-A")];
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            None, // last_findings: fallback path
            None,
            &exclusions,
            None,
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::StillRejected);
    }

    #[test]
    fn still_rejected_with_explicit_policy_threshold() {
        let artifact = rejected_artifact("xz-utils");
        // High finding — threshold High → exceeds → Reject.
        let summary = summary(0, 1, 0, 0);
        let policy = projection(SeverityThreshold::High);
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            None,
            Some(&policy),
            &[],
            None,
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::StillRejected);
    }

    // -- ResetToQuarantined (Clean + future computed deadline) --------------

    #[test]
    fn reset_to_quarantined_when_clean_and_window_in_future() {
        let artifact = rejected_artifact("xz-utils");
        let summary = summary(1, 0, 0, 0);
        let exclusions = vec![exclusion("CVE-A")];
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            None,
            None,
            &exclusions,
            Some(ts(2_000_000)), // computed deadline
            ts(1_000_000),       // now < deadline
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToQuarantined);
    }

    // -- ResetToReleased (Clean + elapsed window) ---------------------------

    #[test]
    fn reset_to_released_when_clean_and_window_elapsed() {
        let summary = summary(1, 0, 0, 0);
        let exclusions = vec![exclusion("CVE-A")];
        let outcome = decide_rejected_transition(
            &rejected_artifact("xz-utils"),
            &summary,
            None,
            None,
            &exclusions,
            Some(ts(1_000_000)), // computed deadline
            ts(2_000_000),       // now > deadline
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }

    #[test]
    fn reset_to_released_when_clean_and_no_quarantine_deadline() {
        // `None` deadline is treated as "elapsed" — no quarantine hold
        // applies, so a clean re-eval lands directly on released.
        let summary = summary(1, 0, 0, 0);
        let exclusions = vec![exclusion("CVE-A")];
        let outcome = decide_rejected_transition(
            &rejected_artifact("xz-utils"),
            &summary,
            None,
            None,
            &exclusions,
            None,
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }

    #[test]
    fn reset_to_released_at_boundary_quarantine_deadline_equals_now() {
        // Boundary: computed deadline == now. The `<=` favouring
        // released is documented in the module rustdoc.
        let summary = summary(1, 0, 0, 0);
        let exclusions = vec![exclusion("CVE-A")];
        let now = ts(2_000_000);
        let outcome = decide_rejected_transition(
            &rejected_artifact("xz-utils"),
            &summary,
            None,
            None,
            &exclusions,
            Some(now),
            now,
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }

    // -- Empty summary (no findings at all) ---------------------------------

    #[test]
    fn empty_summary_with_future_window_resets_to_quarantined() {
        // Defence-in-depth: an artifact rejected in the past whose
        // last-scan summary now reads zero findings (e.g. data-fix path)
        // takes the Clean branch via the time-hold boundary.
        let summary = summary(0, 0, 0, 0);
        let outcome = decide_rejected_transition(
            &rejected_artifact("xz-utils"),
            &summary,
            None,
            None,
            &[],
            Some(ts(2_000_000)),
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToQuarantined);
    }

    #[test]
    fn empty_summary_with_past_window_resets_to_released() {
        let summary = summary(0, 0, 0, 0);
        let outcome = decide_rejected_transition(
            &rejected_artifact("xz-utils"),
            &summary,
            None,
            None,
            &[],
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }

    // -- Enforcement mode (the ADR 0041 loosen direction) --------------------

    fn projection_with_enforcement(
        threshold: SeverityThreshold,
        enforcement: ScanEnforcement,
    ) -> ScanPolicyProjection {
        ScanPolicyProjection {
            enforcement,
            ..projection(threshold)
        }
    }

    #[test]
    fn record_enforcement_un_rejects_a_still_blocking_artifact() {
        // The loosen direction: a scan-rejected artifact
        // whose findings STILL cross the threshold is cleared purely by
        // flipping `enforcement` to `record` — no exclusion, no rescan.
        // The elapsed deadline lands it on Released (release authority
        // #5).
        let artifact = rejected_artifact("xz-utils");
        let summary = summary(1, 0, 0, 0);
        let findings = vec![finding("CVE-REAL", SeverityThreshold::Critical)];
        let policy = projection_with_enforcement(SeverityThreshold::High, ScanEnforcement::Record);
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            Some(&findings),
            Some(&policy),
            &[],
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }

    #[test]
    fn record_enforcement_respects_the_remaining_time_hold() {
        // Loosening the enforcement mode removes the scan block, NOT the
        // observation window (ADR 0007 / quarantine invariant 3) — a
        // still-future deadline returns the artifact to Quarantined.
        let artifact = rejected_artifact("xz-utils");
        let summary = summary(1, 0, 0, 0);
        let findings = vec![finding("CVE-REAL", SeverityThreshold::Critical)];
        let policy = projection_with_enforcement(SeverityThreshold::High, ScanEnforcement::Record);
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            Some(&findings),
            Some(&policy),
            &[],
            Some(ts(2_000_000)),
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToQuarantined);
    }

    #[test]
    fn reject_enforcement_keeps_a_blocking_artifact_rejected() {
        // The complement of the two tests above: the same artifact under
        // the default mode stays rejected. This is what the tighten
        // direction (`record → reject`) re-derives.
        let artifact = rejected_artifact("xz-utils");
        let summary = summary(1, 0, 0, 0);
        let findings = vec![finding("CVE-REAL", SeverityThreshold::Critical)];
        let policy = projection_with_enforcement(SeverityThreshold::High, ScanEnforcement::Reject);
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            Some(&findings),
            Some(&policy),
            &[],
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::StillRejected);
    }

    #[test]
    fn record_enforcement_also_clears_a_negligible_block() {
        // Enforcement sits AFTER the negligible lane, so it clears a
        // `negligibleAction: block` rejection too — the two knobs
        // compose rather than one shadowing the other.
        let artifact = rejected_artifact("proc-macro-error2");
        let summary = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 1,
        };
        let findings = vec![informational_finding("RUSTSEC-2026-0173")];
        let policy = ScanPolicyProjection {
            enforcement: ScanEnforcement::Record,
            ..projection_with_negligible(SeverityThreshold::High, NegligibleAction::Block)
        };
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            Some(&findings),
            Some(&policy),
            &[],
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }

    #[test]
    fn absent_policy_defaults_to_reject_enforcement() {
        // No resolved policy ⇒ `DefaultPolicy::enforcement()` ⇒ Reject:
        // the un-configured repo still enforces its critical block.
        let artifact = rejected_artifact("xz-utils");
        let summary = summary(1, 0, 0, 0);
        let findings = vec![finding("CVE-REAL", SeverityThreshold::Critical)];
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            Some(&findings),
            None,
            &[],
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::StillRejected);
    }

    // -- ReEvaluationOutcome derives -----------------------------------------

    #[test]
    fn outcome_clone_copy_eq() {
        let a = ReEvaluationOutcome::ResetToQuarantined;
        let b = a; // Copy
        #[allow(clippy::clone_on_copy)]
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, ReEvaluationOutcome::StillRejected);
        assert_ne!(a, ReEvaluationOutcome::ResetToReleased);
    }

    #[test]
    fn outcome_debug_formats() {
        // Defence-in-depth — derive(Debug) must produce non-empty output.
        for o in [
            ReEvaluationOutcome::StillRejected,
            ReEvaluationOutcome::ResetToQuarantined,
            ReEvaluationOutcome::ResetToReleased,
        ] {
            assert!(!format!("{o:?}").is_empty());
        }
    }

    // -- Coords-format sentinel ---------------------------------------------

    #[test]
    fn coords_format_sentinel_does_not_affect_outcome() {
        // The function constructs `coords` with `RepositoryFormat::Other("")`
        // — the exclusion filter's `package_pattern` matcher uses
        // `coords.name`, not `coords.format`. Verify that an artifact whose
        // real format would differ still produces the same outcome.
        let mut artifact = rejected_artifact("xz-utils");
        artifact.path = "/xz-utils".into();
        // Real artifacts are stored with their actual format, but the
        // re-evaluator never reads coords.format — Cargo here is just
        // a sanity check that the sentinel didn't leak into a comparison.
        let _format_irrelevant = RepositoryFormat::Cargo;
        let summary = summary(1, 0, 0, 0);
        let exclusions = vec![exclusion("CVE-A")];
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            None,
            None,
            &exclusions,
            None,
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }

    // -- Per-finding path ----------------------------------------------------

    fn finding(vuln: &str, sev: SeverityThreshold) -> Finding {
        Finding {
            purl: "pkg:npm/lodash@4.17.20".into(),
            vulnerability_id: vuln.into(),
            severity: sev,
            cvss_score: None,
            title: "test finding".into(),
            fixed_versions: vec![],
            source_scanner: "osv".into(),
            references: vec![],
            aliases: vec![],
            informational_class: None,
            severity_basis: crate::types::SeverityBasis::Assessed,
        }
    }

    #[test]
    fn per_finding_path_one_exclusion_drops_every_matching_cve() {
        // Motivating case: OSV scanner returns five
        // findings for `lodash@4.17.20`, all carrying the same CVE id
        // (`CVE-2021-23337`). With per-finding matching, ONE exclusion
        // clears all five — the aggregate-summary path would have
        // dropped only one count per exclusion.
        let artifact = rejected_artifact("lodash");
        let summary = SeveritySummary {
            critical: 0,
            high: 2,
            medium: 3,
            low: 0,
            negligible: 0,
        };
        let findings = vec![
            finding("CVE-2021-23337", SeverityThreshold::High),
            finding("CVE-2021-23337", SeverityThreshold::High),
            finding("CVE-2021-23337", SeverityThreshold::Medium),
            finding("CVE-2021-23337", SeverityThreshold::Medium),
            finding("CVE-2021-23337", SeverityThreshold::Medium),
        ];
        let exclusions = vec![ExclusionProjection {
            exclusion_id: Uuid::from_u128(1),
            policy_id: Uuid::from_u128(0xa11ce),
            cve_id: "CVE-2021-23337".into(),
            package_pattern: Some("lodash".into()),
            scope: PolicyScope::Global,
            reason: "patched".into(),
            added_by_actor_id: None,
            expires_at: None,
        }];
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            Some(&findings),
            None,
            &exclusions,
            None,
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }

    #[test]
    fn per_finding_path_unrelated_exclusion_keeps_artifact_rejected() {
        // One CVE-id exclusion targets a different CVE than what the
        // findings list contains. Per-finding path must NOT clear the
        // findings; artifact stays Rejected.
        let artifact = rejected_artifact("lodash");
        let summary = SeveritySummary {
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        let findings = vec![finding("CVE-REAL", SeverityThreshold::Critical)];
        let exclusions = vec![exclusion("CVE-UNRELATED")];
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            Some(&findings),
            None,
            &exclusions,
            None,
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::StillRejected);
    }

    /// An informational/negligible finding: no CVSS score, classified
    /// informational by the advisory DB so it routes onto the negligible
    /// lane (`post_exclusion_summary.negligible == 1`) and never trips a
    /// CVE threshold. The cosmetic `severity` is irrelevant to the
    /// routing — `is_informational()` keys on the class, not severity.
    fn informational_finding(vuln: &str) -> Finding {
        Finding {
            informational_class: Some("unmaintained".to_string()),
            ..finding(vuln, SeverityThreshold::Low)
        }
    }

    fn projection_with_negligible(
        threshold: SeverityThreshold,
        action: NegligibleAction,
    ) -> ScanPolicyProjection {
        ScanPolicyProjection {
            negligible_action: action,
            ..projection(threshold)
        }
    }

    #[test]
    fn informational_finding_under_block_stays_rejected_after_exclusion() {
        // ADR 0040 §3: a `negligible_action: Block` rejection must survive
        // an exclusion-triggered re-evaluation. The finding is CVE-clean
        // (no scored tier) but routes onto the negligible lane; under
        // Block the re-evaluation must keep the artifact Rejected even
        // though an unrelated exclusion was added. This is the regression
        // guard for the helper-shared negligible step in re_evaluation.
        let artifact = rejected_artifact("proc-macro-error2");
        let summary = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 1,
        };
        let findings = vec![informational_finding("RUSTSEC-2026-0173")];
        let policy = projection_with_negligible(SeverityThreshold::High, NegligibleAction::Block);
        // An unrelated exclusion — does not match the informational
        // finding, so the post-exclusion negligible count stays 1.
        let exclusions = vec![exclusion("CVE-UNRELATED")];
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            Some(&findings),
            Some(&policy),
            &exclusions,
            // Deadline in the future — irrelevant under Block, the
            // outcome must be StillRejected regardless.
            Some(ts(2_000_000)),
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::StillRejected);
    }

    #[test]
    fn informational_finding_under_ignore_resets_to_released() {
        // Same CVE-clean informational finding under `negligible_action:
        // Ignore` — the negligible lane is non-enforcing, so the
        // re-evaluation is Clean and the elapsed-deadline boundary lands
        // the artifact on Released.
        let artifact = rejected_artifact("proc-macro-error2");
        let summary = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 1,
        };
        let findings = vec![informational_finding("RUSTSEC-2026-0173")];
        let policy = projection_with_negligible(SeverityThreshold::High, NegligibleAction::Ignore);
        let exclusions = vec![exclusion("CVE-UNRELATED")];
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            Some(&findings),
            Some(&policy),
            &exclusions,
            // Deadline elapsed → ResetToReleased.
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }

    #[test]
    fn per_finding_path_empty_findings_short_circuits_to_released() {
        // Findings slice is empty (e.g. all findings already excluded
        // in a prior pass). No CVE thresholds to violate → released.
        let artifact = rejected_artifact("lodash");
        let summary = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        let exclusions = vec![exclusion("CVE-A")];
        let outcome = decide_rejected_transition(
            &artifact,
            &summary,
            Some(&[]),
            None,
            &exclusions,
            None,
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }
}
