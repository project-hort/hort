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
//! That agreement covers which *findings* reach the verdict too: both
//! functions drop the operator's exclusions and then narrow what is left
//! to the findings that may condemn the artifact
//! ([`crate::types::Finding::may_condemn_artifact`]), in that order and
//! before any threshold is walked. One of the two skipping the narrowing
//! is what leaves an artifact held on a verdict a fresh scan of the same
//! findings would not reach.
//!
//! **The identical question, not identical inputs.** Both functions put
//! the same predicate to the same finding list; one of the predicate's
//! inputs differs between the paths *that drive this one*, deliberately,
//! and the difference is ADR 0064 D6's. `composite_verdict` is a
//! parameter here rather than resolved from `policy`, because the two
//! callers of a re-evaluation are not the same act:
//!
//! * the **automatic loosening** pass — an exclusion added, a threshold
//!   raised, a policy archived — pins
//!   [`CompositeVerdictMode::Observed`]. D6 reserves recovery of the
//!   existing estate to the operator: "constituents already terminally
//!   rejected on filesystem findings are not un-rejected
//!   automatically". With the statement persisted, a resolved posture
//!   here would un-reject exactly that population as a side effect of an
//!   unrelated loosening, with no fresh assessment behind it.
//! * the **operator's explicit curation re-evaluation** passes the
//!   resolved posture, because that is the sanctioned recovery D6 points
//!   at. Nothing is silent about it: a curator asked for this artifact to
//!   be judged again.
//! * the **tighten** direction goes through
//!   [`crate::policy::evaluate_scan_result`], which resolves the posture
//!   from the policy it is already under — the same way a fresh scan
//!   does, and necessarily so: a pinned `Observed` there would re-reject
//!   the constituent a promoted fresh scan had just let through, on the
//!   next threshold change, terminally.
//!
//! So the asymmetry is between *drivers*, not between the two verdict
//! functions, and it is stated at each call site with its reason.
//!
//! The one place the two functions knowingly differ is the
//! aggregate-summary fallback, which has no per-finding data to narrow —
//! an accepted, fail-closed residual documented on
//! [`decide_rejected_transition`].
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
use crate::entities::scan_policy::{
    CompositeVerdictMode, ExclusionProjection, ScanEnforcement, ScanPolicyProjection,
};
use crate::events::SeveritySummary;
use crate::types::{severity_summary_from_findings, ArtifactCoords, ArtifactKind, Finding};

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
///    The survivors are then narrowed by
///    [`crate::types::Finding::may_condemn_artifact`] — step 1b of
///    [`crate::policy::evaluate_scan_result`], applied here at the
///    equivalent point — and the aggregate both tier inputs read is
///    recomputed over what is left. A finding naming a component whose
///    code the artifact does not carry keeps its place in the record and
///    loses its authority over this artifact's release gate (ADR 0056 as
///    amended). Both verdict functions must apply it or they answer
///    differently about one finding list; see the body for the sequence
///    that strands an artifact when only one of them does.
///
/// 2. **Aggregate-summary fallback** — when
///    `last_findings` is `None`, [`filter_excluded_summary`] applies
///    the highest-tier-first decrement: each active+pattern-matching
///    exclusion decrements one count from the highest non-zero tier
///    (Critical → High → Medium → Low). Preserved bit-for-bit
///    for callers that cannot resolve the `findings_blob`
///    (clean scans, missing CAS object, deserialise failure).
///
///    **This path cannot narrow the condemning set, and that is an
///    accepted residual rather than an inconsistency.** Per-tier counts
///    carry no per-finding data, so there is nothing to ask
///    [`crate::types::Finding::may_condemn_artifact`] about: a finding
///    naming a component the artifact does not carry keeps the release
///    authority the per-finding mode above denies it, because on this
///    path nothing records that it was such a finding. The divergence is
///    fail-closed — a degraded read holds an artifact the per-finding
///    verdict might have cleared, never the reverse — and it is the one
///    this path already takes with `severity_basis`, which a count
///    cannot carry either (a `critical: 1` does not say whether that
///    Critical was assessed or was the unreadable-advisory floor).
///    Reconstructing the relation from counts would mean inventing it,
///    and the fail-closed reading of absent evidence is that the finding
///    still counts (ADR 0007); the correctable path is a rescan, which
///    re-establishes the relation and re-enters mode 1.
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
/// `kind` is what the artifact's own format handler says its bytes are,
/// resolved by the application caller through the handler registry (never
/// from a path prefix, which would be a second copy of `scan_kind`). It
/// is the role half of ADR 0064 D2's line — see
/// [`crate::types::Finding::may_condemn_artifact`].
///
/// `composite_verdict` is a **parameter, not a resolution**, and that is
/// the one input on which the drivers of a re-evaluation deliberately
/// differ: the automatic loosening pass pins
/// [`CompositeVerdictMode::Observed`] so that promotion never un-rejects
/// a terminal constituent by itself, while the operator's explicit
/// curation re-evaluation passes
/// [`crate::policy::composite_verdict_mode_of`]'s answer so the
/// sanctioned recovery still works. The module rustdoc gives the full
/// reason (ADR 0064 D6); a caller choosing between them is choosing which
/// act this is, and must say so where it chooses.
///
/// See module rustdoc for the boundary semantics
/// (`quarantine_deadline <= now` favours `ResetToReleased`).
#[allow(clippy::too_many_arguments)]
pub fn decide_rejected_transition(
    artifact: &Artifact,
    kind: ArtifactKind,
    last_scan_summary: &SeveritySummary,
    last_findings: Option<&[Finding]>,
    policy: Option<&ScanPolicyProjection>,
    updated_exclusions: &[ExclusionProjection],
    composite_verdict: CompositeVerdictMode,
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
    // `scan_history::last_findings` already logged a warn for the corruption
    // cases).
    let post_exclusion_summary = match last_findings {
        Some(findings) => {
            // The exclusion filter, then step 1b — the same two questions
            // `evaluate_scan_result` asks of the same input, in the same
            // order, before any threshold exists to walk: which findings
            // survive the operator's exclusions, and which of those may
            // decide THIS artifact's verdict.
            //
            // A finding naming a component whose code the artifact does
            // not carry is real information about that component — the
            // payload resolved its coordinates out of a manifest or
            // lockfile it ships, and a consumer's build resolves none of
            // those pins — but it is not evidence about this artifact, so
            // it has no authority over this artifact's release gate
            // (ADR 0056 as amended). It stays in the record: this function
            // reads `last_findings` and writes nothing, so the stored blob
            // and the `ScanCompleted` aggregate are untouched and the
            // operator still sees the finding present and counted.
            //
            // The narrowing has to happen on BOTH verdict paths or they
            // answer differently about one finding list, and the direction
            // the disagreement breaks in is the one that strands an
            // artifact: a rejection over a carried finding, an exclusion
            // added for it, and the non-carried leftover read as blocking
            // here while a fresh scan of the identical findings comes back
            // clean. Fail-closed, but held on a verdict no scan would
            // reach and clearable only by a rescan.
            //
            // The narrowed aggregate is the arm's only result, so every
            // tier input below — the CVE walk and the negligible lane
            // alike — is derived from the findings it governs; an
            // un-narrowed summary is never bound and so cannot be read by
            // whichever one a later edit forgets.
            //
            // `Finding::may_condemn_artifact` is the single definition of
            // the question; re-deriving it by matching on the relation — or
            // on the statement — here is what
            // `hort-app/tests/condemning_rule_is_single_sourced.rs`
            // rejects.
            //
            // `kind` and `composite_verdict` are the two inputs the
            // predicate's second question needs (ADR 0064 D2): what each
            // finding's statement is about depends on the row's role as
            // well as on what the producer read. Both arrive from the
            // caller — `kind` resolved from the artifact's own format
            // handler, the posture *chosen* rather than resolved, because
            // the loosening pass and the operator's curation
            // re-evaluation are different acts with different answers.
            // See this function's rustdoc and the module docs.
            let filtered = filter_excluded_findings(findings, updated_exclusions, &coords, now);
            let mut condemning = filtered.remaining_findings;
            condemning.retain(|f| f.may_condemn_artifact(kind, composite_verdict));
            severity_summary_from_findings(&condemning)
        }
        // The aggregate-summary fallback cannot consult the relation —
        // per-tier counts carry no per-finding data. See this function's
        // rustdoc: an accepted, fail-closed residual, not an oversight.
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
    use crate::entities::scan_policy::CompositeVerdictMode;
    use crate::entities::scan_policy::{NegligibleAction, ProvenanceMode, SeverityThreshold};
    use crate::events::PolicyScope;
    use crate::policy::{composite_verdict_mode_of, evaluate_scan_result, ScanOutcome};
    use crate::types::{ComponentRelation, ContentHash, Finding};
    use chrono::TimeZone;
    use uuid::Uuid;

    const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// The kind every test below hands the predicate unless it is about
    /// the role half of ADR 0064 D2's line: a row that is **not** a
    /// composition constituent, so nothing in the statement axis can be
    /// what produced the outcome being asserted.
    const TEST_KIND: ArtifactKind = ArtifactKind::NpmTarball;

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
            provenance_hold_indefinite: false,
            deleted_at: None,
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
            composite_verdict_mode: CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            None, // last_findings: fallback path
            None,
            &exclusions,
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            None,
            Some(&policy),
            &[],
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            None,
            None,
            &exclusions,
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            None,
            None,
            &exclusions,
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            None,
            None,
            &exclusions,
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            None,
            None,
            &exclusions,
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            None,
            None,
            &[],
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            None,
            None,
            &[],
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            Some(&findings),
            Some(&policy),
            &[],
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            Some(&findings),
            Some(&policy),
            &[],
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            Some(&findings),
            Some(&policy),
            &[],
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            Some(&findings),
            Some(&policy),
            &[],
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            Some(&findings),
            None,
            &[],
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            None,
            None,
            &exclusions,
            CompositeVerdictMode::Observed,
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
            component_relation: ComponentRelation::NotEstablished,
            statement: crate::types::FindingStatement::Unstated,
            advisory_published_at: None,
        }
    }

    /// A stored finding as the Trivy adapter produced it from a
    /// `Vulnerabilities` entry — a claim about the filesystem the
    /// materialised bytes compose into, which **persists**, so this is
    /// what a hydrated constituent finding actually looks like.
    fn filesystem_finding(vuln: &str, sev: SeverityThreshold) -> Finding {
        let mut f = finding(vuln, sev);
        f.statement = crate::types::FindingStatement::Filesystem;
        f
    }

    /// **ADR 0064 D6: the loosening does not reach the already-rejected
    /// estate.** A constituent rejected on its own filesystem findings
    /// stays rejected when the *automatic* loosening pass recomputes its
    /// verdict, even where the policy that governs it has promoted the
    /// composite verdict.
    ///
    /// **This passes for a different reason than it used to, and the
    /// reason is the point of the change.** It used to pass because the
    /// statement did not persist: a hydrated finding read `Unstated`, so
    /// there was nothing for a loosening to key on — and the same absence
    /// made the tighten pass terminally reject constituents a promoted
    /// fresh scan had just released. The statement now persists, so the
    /// stored finding below really does say `Filesystem` and the row
    /// really is a constituent; what holds D6 is the posture this path
    /// **pins**, `CompositeVerdictMode::Observed`, which is the input the
    /// caller chooses rather than resolves. A test that still passed
    /// after its mechanism changed is a test nobody re-read, so: the
    /// assertion below is now about the pin.
    ///
    /// Asserted against the same input under both *policies*, because the
    /// claim is that the policy's posture makes no difference on this
    /// path — the pin is what answers. An un-rejection here would be a
    /// population released with no fresh assessment, which is the hazard
    /// that disqualified `ScanEnforcement::Record` for this job in the
    /// first place.
    ///
    /// Recovering the estate is the operator's, through the curation
    /// re-evaluation, which passes the resolved posture instead —
    /// `the_operators_curation_re_evaluation_can_recover_the_same_row`
    /// is the other half of the pair.
    #[test]
    fn a_promoted_policy_does_not_un_reject_a_constituent_over_its_stored_findings() {
        let artifact = rejected_artifact("lodash");
        let summary = summary(1, 0, 0, 0);
        // What the stored findings blob yields, through the blob: a
        // filesystem claim the producer made and the wire form kept.
        let blob = serde_json::to_string(&[filesystem_finding(
            "CVE-2021-23337",
            SeverityThreshold::Critical,
        )])
        .unwrap();
        let stored: Vec<Finding> = serde_json::from_str(&blob).unwrap();
        assert_eq!(
            stored[0].statement,
            crate::types::FindingStatement::Filesystem,
            "the premise: the loosening now has a real statement in front of it",
        );

        let promoted = ScanPolicyProjection {
            composite_verdict_mode: CompositeVerdictMode::Promoted,
            ..projection(SeverityThreshold::Critical)
        };
        for policy in [projection(SeverityThreshold::Critical), promoted] {
            let outcome = decide_rejected_transition(
                &artifact,
                // A constituent — the one kind whose filesystem claim
                // could move at all, so the pin is what is being tested
                // rather than the kind.
                ArtifactKind::OciBlob,
                &summary,
                Some(&stored),
                Some(&policy),
                &[],
                // The automatic loosening pass's pin.
                CompositeVerdictMode::Observed,
                None,
                ts(1_000_000),
            );
            assert_eq!(
                outcome,
                ReEvaluationOutcome::StillRejected,
                "composite_verdict_mode = {} must not move a terminal row",
                policy.composite_verdict_mode
            );
        }
    }

    /// The other half of the pair D6 requires: the operator's explicit
    /// curation re-evaluation passes the **resolved** posture, so the
    /// sanctioned recovery of the same row works.
    ///
    /// Without this, the pin above would not be an asymmetry between two
    /// drivers — it would be a dead end, and D6's "recovering the existing
    /// estate is operator-driven, through the curation re-evaluation"
    /// would name a path that cannot do it.
    #[test]
    fn the_operators_curation_re_evaluation_can_recover_the_same_row() {
        let artifact = rejected_artifact("lodash");
        let summary = summary(1, 0, 0, 0);
        let stored = vec![filesystem_finding(
            "CVE-2021-23337",
            SeverityThreshold::Critical,
        )];
        let promoted = ScanPolicyProjection {
            composite_verdict_mode: CompositeVerdictMode::Promoted,
            ..projection(SeverityThreshold::Critical)
        };

        let outcome = decide_rejected_transition(
            &artifact,
            ArtifactKind::OciBlob,
            &summary,
            Some(&stored),
            Some(&promoted),
            &[],
            // What the curation endpoint passes: the posture the policy
            // actually resolves to.
            composite_verdict_mode_of(Some(&promoted)),
            None,
            ts(1_000_000),
        );
        assert_eq!(
            outcome,
            ReEvaluationOutcome::ResetToReleased,
            "a curator asked for this row to be judged again, and under the \
             policy's own promoted posture its isolated package set is \
             evidence rather than the verdict",
        );
    }

    /// And the kind still scopes it: the operator's re-evaluation of a
    /// **non**-constituent row under the same promoted policy keeps the
    /// rejection. The recovery D6 sanctions is of constituents, not of
    /// everything a global policy reaches.
    #[test]
    fn the_operators_re_evaluation_does_not_recover_a_non_constituent_row() {
        let artifact = rejected_artifact("lodash");
        let summary = summary(1, 0, 0, 0);
        let stored = vec![filesystem_finding(
            "CVE-2021-23337",
            SeverityThreshold::Critical,
        )];
        let promoted = ScanPolicyProjection {
            composite_verdict_mode: CompositeVerdictMode::Promoted,
            ..projection(SeverityThreshold::Critical)
        };

        let outcome = decide_rejected_transition(
            &artifact,
            TEST_KIND,
            &summary,
            Some(&stored),
            Some(&promoted),
            &[],
            composite_verdict_mode_of(Some(&promoted)),
            None,
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::StillRejected);
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
            TEST_KIND,
            &summary,
            Some(&findings),
            None,
            &exclusions,
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            Some(&findings),
            None,
            &exclusions,
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            Some(&findings),
            Some(&policy),
            &exclusions,
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            Some(&findings),
            Some(&policy),
            &exclusions,
            CompositeVerdictMode::Observed,
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
            TEST_KIND,
            &summary,
            Some(&[]),
            None,
            &exclusions,
            CompositeVerdictMode::Observed,
            None,
            ts(1_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }

    // ---- which findings may condemn, on the re-evaluation path ----
    //
    // Same order and the same reasoning as the sibling block in
    // `crate::policy::scan`: the directions the narrowing must NOT touch
    // come first, because an over-broad predicate disarms the gate
    // silently — every test that only checks "the bad artifact stayed
    // rejected" keeps passing on the cases it still catches. The
    // elapsed-deadline shape (`Some(ts(1_000_000))`, `ts(2_000_000)`) is
    // used throughout so a cleared verdict reads as `ResetToReleased` and
    // the time hold cannot be what decided the assertion.

    /// `finding`, re-tagged with the relation under test — the only thing
    /// that differs between the cases below.
    fn about(relation: ComponentRelation, mut f: Finding) -> Finding {
        f.component_relation = relation;
        f
    }

    /// The [`ArtifactCoords`] `decide_rejected_transition` derives from
    /// `artifact` internally, format sentinel included, so a comparison
    /// against [`evaluate_scan_result`] runs the other verdict function
    /// over the same inputs rather than merely similar ones.
    fn coords_of(artifact: &Artifact) -> ArtifactCoords {
        ArtifactCoords {
            name: artifact.name.clone(),
            name_as_published: artifact.name_as_published.clone(),
            version: artifact.version.clone(),
            path: artifact.path.clone(),
            format: RepositoryFormat::Other(String::new()),
            metadata: serde_json::Value::Null,
        }
    }

    /// A Critical about the artifact's **own** subject component — the
    /// case that keeps full release authority, and the one an over-broad
    /// narrowing would break here and nowhere else obvious.
    fn subject_critical(vuln: &str) -> Finding {
        about(
            ComponentRelation::Subject,
            finding(vuln, SeverityThreshold::Critical),
        )
    }

    /// A Critical about a component the artifact does **not** carry — the
    /// `h2` pinned in a published crate's embedded `Cargo.lock`, whose
    /// code the `.crate` does not ship and no consumer's build resolves.
    fn not_contained_critical(vuln: &str) -> Finding {
        about(
            ComponentRelation::NotContained,
            finding(vuln, SeverityThreshold::Critical),
        )
    }

    #[test]
    fn a_subject_component_finding_keeps_the_artifact_rejected() {
        let artifact = rejected_artifact("hyper-util");
        let findings = vec![subject_critical("CVE-SUBJECT")];
        let outcome = decide_rejected_transition(
            &artifact,
            TEST_KIND,
            &summary(1, 0, 0, 0),
            Some(&findings),
            None,
            &[],
            CompositeVerdictMode::Observed,
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(
            outcome,
            ReEvaluationOutcome::StillRejected,
            "a finding about the artifact itself keeps full release authority",
        );
    }

    #[test]
    fn a_contained_component_finding_keeps_the_artifact_rejected() {
        // A format whose payload carries its closure — an OCI image and
        // its layers. Not the subject, and the code IS in the artifact,
        // so it condemns unchanged; collapsing this into the subject case
        // would disarm every layer finding on every image.
        let artifact = rejected_artifact("app");
        let findings = vec![about(
            ComponentRelation::Contained,
            finding("CVE-LAYER", SeverityThreshold::Critical),
        )];
        let outcome = decide_rejected_transition(
            &artifact,
            TEST_KIND,
            &summary(1, 0, 0, 0),
            Some(&findings),
            None,
            &[],
            CompositeVerdictMode::Observed,
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::StillRejected);
    }

    #[test]
    fn a_not_established_relation_keeps_the_artifact_rejected() {
        // A record whose relation was never established — every finding
        // persisted before the field existed, which on this path means
        // every blob already in CAS — must keep today's behaviour.
        // Defaulting the other way would disarm the whole stored corpus
        // in one step (ADR 0007).
        let artifact = rejected_artifact("any");
        let findings = vec![about(
            ComponentRelation::NotEstablished,
            finding("CVE-LEGACY", SeverityThreshold::Critical),
        )];
        let outcome = decide_rejected_transition(
            &artifact,
            TEST_KIND,
            &summary(1, 0, 0, 0),
            Some(&findings),
            None,
            &[],
            CompositeVerdictMode::Observed,
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::StillRejected);
    }

    #[test]
    fn a_not_contained_component_finding_no_longer_keeps_the_artifact_rejected() {
        // The narrowing itself, and the half that keeps it honest: the
        // finding loses its hold on the artifact AND is still in the
        // caller's list afterwards. This function reads the slice and
        // writes nothing, so the stored blob and the `ScanCompleted`
        // aggregate it was hydrated from are untouched — implementing the
        // rule as a removal from the record would trade one wrong answer
        // for another.
        let artifact = rejected_artifact("hyper-util");
        let findings = vec![not_contained_critical("CVE-ELSEWHERE")];
        let outcome = decide_rejected_transition(
            &artifact,
            TEST_KIND,
            &summary(1, 0, 0, 0),
            Some(&findings),
            None,
            &[],
            CompositeVerdictMode::Observed,
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(
            outcome,
            ReEvaluationOutcome::ResetToReleased,
            "a Critical about code the artifact does not carry has no \
             authority over this artifact's release",
        );
        assert_eq!(findings.len(), 1, "the finding stays in the caller's list");
        assert_eq!(findings[0].severity, SeverityThreshold::Critical);
        assert_eq!(
            findings[0].component_relation,
            ComponentRelation::NotContained,
        );
    }

    #[test]
    fn the_two_verdict_functions_agree_once_the_subject_finding_is_excluded() {
        // The sequence that made this unit necessary, end to end: an
        // artifact rejected over a Critical about its own subject that
        // ALSO carries a Critical about a component it does not ship; the
        // operator excludes the subject one. Before the narrowing reached
        // this function, the leftover non-carried Critical read as
        // blocking and the artifact stayed `Rejected` — while a fresh
        // scan of the identical findings came back `Clean`. Fail-closed,
        // but held on a verdict no scan would reach, clearable only by a
        // rescan.
        //
        // Both functions are run over the same findings, the same
        // exclusion set and the same coords, so the assertion is about
        // the two agreeing rather than about one of them in isolation.
        let artifact = rejected_artifact("hyper-util");
        let findings = vec![
            subject_critical("CVE-SUBJECT"),
            not_contained_critical("CVE-ELSEWHERE"),
        ];
        let exclusions = vec![exclusion("CVE-SUBJECT")];
        let now = ts(2_000_000);

        let fresh_scan = evaluate_scan_result(
            &coords_of(&artifact),
            TEST_KIND,
            &findings,
            None,
            &exclusions,
            now,
        );
        assert_eq!(
            fresh_scan,
            ScanOutcome::Clean,
            "a fresh scan of these findings under this exclusion is clean",
        );

        let re_evaluated = decide_rejected_transition(
            &artifact,
            TEST_KIND,
            &summary(2, 0, 0, 0),
            Some(&findings),
            None,
            &exclusions,
            CompositeVerdictMode::Observed,
            Some(ts(1_000_000)),
            now,
        );
        assert_eq!(
            re_evaluated,
            ReEvaluationOutcome::ResetToReleased,
            "re-evaluation must reach the same verdict as the fresh scan \
             the operator could have triggered instead; `StillRejected` \
             here is an artifact stranded on a verdict no scan produces",
        );
    }

    #[test]
    fn the_two_verdict_functions_agree_that_a_non_carried_finding_alone_is_clean() {
        // The acceptance shape stated as one assertion over both
        // functions: a finding list carrying nothing but non-carried
        // findings yields a non-blocking outcome from each.
        let artifact = rejected_artifact("hyper-util");
        let findings = vec![
            not_contained_critical("CVE-ELSEWHERE"),
            about(
                ComponentRelation::NotContained,
                finding("CVE-ALSO-ELSEWHERE", SeverityThreshold::High),
            ),
        ];

        let fresh_scan = evaluate_scan_result(
            &coords_of(&artifact),
            TEST_KIND,
            &findings,
            None,
            &[],
            ts(2_000_000),
        );
        let re_evaluated = decide_rejected_transition(
            &artifact,
            TEST_KIND,
            &summary(1, 1, 0, 0),
            Some(&findings),
            None,
            &[],
            CompositeVerdictMode::Observed,
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(fresh_scan, ScanOutcome::Clean);
        assert_eq!(re_evaluated, ReEvaluationOutcome::ResetToReleased);
    }

    #[test]
    fn a_not_contained_informational_finding_no_longer_blocks_the_negligible_lane() {
        // The negligible lane reads the SAME narrowed aggregate as the
        // CVE walk, or a non-carried finding would still block through
        // whichever input was missed — and under
        // `negligible_action: Block` the lane is the only path a
        // CVE-clean finding can block through. The complement, an
        // informational finding whose relation is `NotEstablished`, is
        // `informational_finding_under_block_stays_rejected_after_exclusion`
        // above and still blocks.
        let artifact = rejected_artifact("proc-macro-error2");
        let summary = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 1,
        };
        let findings = vec![about(
            ComponentRelation::NotContained,
            informational_finding("RUSTSEC-2026-0173"),
        )];
        let policy = projection_with_negligible(SeverityThreshold::High, NegligibleAction::Block);
        let outcome = decide_rejected_transition(
            &artifact,
            TEST_KIND,
            &summary,
            Some(&findings),
            Some(&policy),
            &[],
            CompositeVerdictMode::Observed,
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(outcome, ReEvaluationOutcome::ResetToReleased);
    }

    #[test]
    fn the_aggregate_summary_fallback_cannot_narrow_and_keeps_condemning() {
        // The accepted residual, pinned as behaviour so the rustdoc
        // paragraph has something holding it: with the blob unhydratable
        // (`last_findings: None`) there are only per-tier counts, nothing
        // records which component each count was about, and the Critical
        // keeps its hold. The same findings in hand answer `Clean`.
        //
        // This asserts a known divergence, deliberately: it is
        // fail-closed (a degraded read holds an artifact the per-finding
        // verdict would have cleared, never the reverse) and a rescan
        // re-establishes the relation. A future change that makes the
        // aggregate path relation-aware should update this test and the
        // rustdoc together.
        let artifact = rejected_artifact("hyper-util");
        let findings = vec![not_contained_critical("CVE-ELSEWHERE")];

        let with_findings = decide_rejected_transition(
            &artifact,
            TEST_KIND,
            &summary(1, 0, 0, 0),
            Some(&findings),
            None,
            &[],
            CompositeVerdictMode::Observed,
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        let blob_unhydratable = decide_rejected_transition(
            &artifact,
            TEST_KIND,
            &summary(1, 0, 0, 0),
            None,
            None,
            &[],
            CompositeVerdictMode::Observed,
            Some(ts(1_000_000)),
            ts(2_000_000),
        );
        assert_eq!(with_findings, ReEvaluationOutcome::ResetToReleased);
        assert_eq!(
            blob_unhydratable,
            ReEvaluationOutcome::StillRejected,
            "per-tier counts cannot say which component a count was \
             about, so the fail-closed reading keeps the artifact held",
        );
    }
}
