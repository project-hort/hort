//! Scan-result evaluation entry point.
//!
//! Composes
//! the per-rule evaluators ([`crate::policy::exclusion`],
//! [`crate::policy::cve`], [`crate::policy::license`]) into a single
//! decision the `QuarantineUseCase::record_scan_result` path calls per
//! incoming `ScanCompleted` event.
//!
//! Pure domain — zero I/O, zero `tracing`, zero allocation beyond the
//! returned violation list. The caller (application layer) is
//! responsible for resolving the active policy + exclusions via outbound
//! ports and translating the [`ScanOutcome`] into emitted events.
//!
//! ## Composition
//!
//! 1. [`crate::policy::exclusion::filter_excluded_findings`] removes
//!    findings whose `(vulnerability_id, package_pattern)` is matched
//!    by an active exclusion. Exact CVE-ID matching against
//!    `ExclusionProjection.cve_id`. The post-exclusion
//!    [`SeveritySummary`] is computed from the surviving findings —
//!    single source of truth.
//!
//!    Then (step 1b in the body)
//!    [`crate::types::Finding::may_condemn_artifact`] narrows the
//!    survivors to the findings that may decide *this* artifact's
//!    verdict: one naming a component whose code the artifact does not
//!    carry — or making a filesystem claim about a tree that belongs to
//!    a composition rather than to this row (`kind` plus the resolved
//!    posture, ADR 0064 D2) — is dropped from the **condemning** set, and
//!    the summary the tier walk and the negligible lane read is
//!    recomputed over what is left. Nothing is removed from the record —
//!    see that predicate and ADR 0056's 2026-10-15 amendment.
//!
//!    [`crate::policy::decide_rejected_transition`] applies the same
//!    narrowing at the same point, because it is the other function that
//!    computes a blocking verdict from a finding list and the two must
//!    not disagree about which findings may decide one. Those are the
//!    predicate's only two consumers; a third would be the moment to
//!    collapse the verdict functions instead.
//! 2. Threshold resolved from `policy.severity_threshold` if a policy
//!    was provided, else [`DefaultPolicy::block_on_critical`] (only
//!    `critical` findings block when no operator policy is configured).
//! 3. [`crate::policy::cve::evaluate_cve_thresholds`] produces one
//!    violation per non-zero severity tier above the threshold; fed
//!    through
//!    [`ViolationsAccumulator::collect_with_severity_escalation`].
//! 4. If `policy.license_policy` is a non-empty JSON object,
//!    [`crate::policy::license::evaluate_license_policy`] runs and is
//!    fed through
//!    [`ViolationsAccumulator::collect_with_policy_action`] using its
//!    returned [`PolicyAction`].
//! 5. `accumulator.into_outcome()` produces
//!    `(action, violations)`. `Block` → [`ScanOutcome::Reject`] under
//!    `enforcement = reject` and [`ScanOutcome::FindingsRecorded`] under
//!    `enforcement = record`; anything else → [`ScanOutcome::Clean`].
//!    `Warn` outcomes do not block in the scan path — a `Warn`-only
//!    result is clean regardless of enforcement; `Warn` violations would
//!    surface as [`crate::events::PolicyEvaluated`] entries on a future
//!    enhancement but do not affect quarantine state today.
//!
//! ## Enforcement mode
//!
//! [`ScanEnforcement`] is the last step, and only the last step: every
//! rule above runs identically in both modes, so the *verdict* (which
//! violations fired, at what severity) is mode-independent and the
//! recorded audit trail is byte-identical. `record` changes only what the
//! caller is told to do with a blocking verdict — record it, do not
//! transition. Keeping the branch here rather than in the caller is what
//! makes the tighten/loosen re-evaluation directions (ADR 0041) fall out
//! of the same single evaluator both other callers already use.
//!
//! ## License-input shape note
//!
//! The `licenses: &[String]` parameter to
//! [`crate::policy::license::evaluate_license_policy`] is the
//! aggregate license list extracted from the artifact's SBOM. v1 has
//! no SBOM port wired into the scan-result path, so this entry point
//! passes `&[]`. The license evaluator's "no licenses found" path is
//! a quiet pass-through (zero violations), so this still surfaces
//! `license-policy-shape` violations when the operator's stored policy
//! JSON is malformed — those are the only license-shaped outcomes the
//! v1 scan path can produce. License-content violations (denied
//! license, unknown license) become reachable in this code path when
//! a follow-on item wires the SBOM port.

use chrono::{DateTime, Utc};

use crate::entities::scan_policy::{
    CompositeVerdictMode, ExclusionProjection, NegligibleAction, ScanEnforcement,
    ScanPolicyProjection, SeverityThreshold,
};
use crate::events::PolicyViolation;
use crate::types::{severity_summary_from_findings, ArtifactCoords, ArtifactKind, Finding};

use super::cve::evaluate_cve_thresholds;
use super::exclusion::filter_excluded_findings;
use super::license::evaluate_license_policy;
use super::primitives::{PolicyAction, ViolationsAccumulator};

/// Rule id stamped on the [`PolicyViolation`] emitted by the
/// `negligible_action` enforcement step (Warn / Block). Distinct from
/// [`crate::policy::cve::RULE`] so audit consumers can tell an
/// informational-advisory block apart from a scored-CVE block.
pub const NEGLIGIBLE_RULE: &str = "negligible-advisory";

/// Outcome of evaluating a scan result against the active policy.
///
/// Three-valued: the two enforcement-worthy verdicts a `Block` can
/// produce ([`Reject`](Self::Reject) / [`FindingsRecorded`](Self::FindingsRecorded),
/// selected by the policy's [`ScanEnforcement`]) plus
/// [`Clean`](Self::Clean). Future enhancements that surface `Warn`
/// outcomes through `PolicyEvaluated(Pass, violations)` extend this
/// enum rather than reinterpreting `Clean`.
///
/// Not [`serde::Serialize`] — domain outcome enum, not an event payload.
/// [`PolicyViolation`] (which IS serialised as part of the
/// `PolicyEvaluated` event) carries the persisted shape.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanOutcome {
    /// Scan produced no enforcement-worthy findings under the active
    /// policy. The artifact's quarantine state is unchanged — the
    /// time-based sweep handles release per quarantine invariant 2.
    Clean,
    /// Scan produced findings that the active policy (or default)
    /// blocks, under `enforcement = reject`. Caller emits
    /// `PolicyEvaluated(Fail, violations)` + `ArtifactRejected`.
    Reject(Vec<PolicyViolation>),
    /// Scan produced the SAME blocking violations as
    /// [`Reject`](Self::Reject), but the active policy declares
    /// `enforcement = record`: the caller emits
    /// `PolicyEvaluated(Fail, violations)` and persists the findings
    /// exactly as it would on a reject, and emits **no**
    /// `ArtifactRejected` — the artifact's quarantine status is
    /// untouched by the verdict.
    ///
    /// Distinct from `Clean` because the audit trail, the metrics and the
    /// operator-facing log line must say which of the two happened: an
    /// operator reading a clean evaluation must never be looking at a
    /// scope that recorded over-threshold findings.
    FindingsRecorded(Vec<PolicyViolation>),
}

/// Default-policy fallback used when the artifact's repository has no
/// active policy resolved. Lives next to [`evaluate_scan_result`] for
/// now — promote to a shared module if the curation gate needs it too.
///
/// The policy-name for log/audit attribution is "default" — there is
/// no [`crate::events::PolicyEvaluated::policy_id`] when the default
/// fired (an absent policy_id implies "no operator policy was active").
pub struct DefaultPolicy;

impl DefaultPolicy {
    /// Threshold used when no operator policy is configured: only
    /// `critical` findings block. `high` and below pass through as
    /// clean.
    pub const fn block_on_critical() -> SeverityThreshold {
        SeverityThreshold::Critical
    }

    /// Default `scan_backends` when no operator policy is configured
    /// for a repo.
    ///
    /// Returns `vec!["trivy"]` — Trivy is the always-on baseline
    /// backend for out-of-the-box deployments. Operators who want
    /// additional backends (e.g. OSV) declare a `ScanPolicy` with an
    /// explicit `scanBackends:` list; operators who want NO scanning
    /// declare a `ScanPolicy` with `scanBackends: []`.
    ///
    /// Out-of-the-box deployments scan with Trivy and block on
    /// critical CVEs. Returns an owned `Vec` rather than a `&'static`
    /// slice so callers can freely mutate or move the result.
    pub fn block_on_critical_default_backends() -> Vec<String> {
        vec!["trivy".to_string()]
    }

    /// Default `rescan_interval_hours` when no
    /// operator policy is configured (or when a policy YAML omits the
    /// field).
    ///
    /// Returns `24` — out-of-the-box deployments rescan artifacts
    /// every 24 hours. Operators who want a different cadence declare
    /// a `ScanPolicy` with an explicit `rescanIntervalHours:` value;
    /// operators who want to disable rescanning entirely declare
    /// `rescanIntervalHours: 0`.
    ///
    /// Default 24h; a value of `0` disables rescanning for that
    /// policy entirely. The constant is load-bearing: the YAML
    /// deserializer's `default = "default_rescan_interval_hours"` and
    /// migration 005's `DEFAULT 24` both refer back to this value.
    pub const fn rescan_interval_hours() -> i32 {
        24
    }

    /// Default quarantine observation-window duration
    /// when no operator `ScanPolicy` is configured.
    ///
    /// Returns `86_400` (24 hours). Out-of-the-box deployments are
    /// quarantine-by-default: every fresh ingest in a repository with
    /// no resolved `ScanPolicy` is held for 24 hours while the scan
    /// pipeline runs. The window starts at the immutable ingest-time
    /// anchor stamped on the artifact; the live deadline is computed
    /// via [`effective_quarantine_deadline`] — the anchor is persisted,
    /// the deadline is never persisted.
    ///
    /// Operators who want a different window declare a `ScanPolicy`
    /// with `quarantineDuration: <secs>`; operators who want
    /// permissive ingest (no hold; bad scans transition straight to
    /// `Rejected`) declare a `ScanPolicy` with `quarantineDuration: 0`.
    /// An explicit operator zero is honoured — it does NOT fall back
    /// to this default. See ADR 0007 (quarantine-by-default posture).
    pub const fn quarantine_duration_secs() -> i64 {
        86_400
    }

    /// Default `negligible_action` when no operator `ScanPolicy` is
    /// configured for a repo.
    ///
    /// Returns [`NegligibleAction::Ignore`] — the no-policy path treats
    /// negligible / informational findings as non-blocking, matching the
    /// negligible tier's never-enforced contract. Operators who want
    /// these advisories to warn or block declare a `ScanPolicy` with an
    /// explicit `negligibleAction:`.
    pub const fn negligible_action() -> NegligibleAction {
        NegligibleAction::Ignore
    }

    /// Default `enforcement` when no operator `ScanPolicy` is configured
    /// for a repo.
    ///
    /// Returns [`ScanEnforcement::Reject`] — an unconfigured repo blocks
    /// on a critical finding (see [`Self::block_on_critical`]) and that
    /// block is enforced. Non-enforcement is an explicit operator
    /// declaration (`enforcement: record`), never a fallback.
    pub const fn enforcement() -> ScanEnforcement {
        ScanEnforcement::Reject
    }

    /// Default `composite_verdict_mode` when no operator `ScanPolicy` is
    /// configured for a repo (ADR 0064 D6).
    ///
    /// Returns [`CompositeVerdictMode::Observed`] — the composed image of
    /// an OCI manifest is still assessed and recorded, and its verdict
    /// decides nothing. This is the one default whose fail-safe direction
    /// runs the *other* way from [`Self::enforcement`]'s: promotion is an
    /// operator act against named criteria, because a composite verdict
    /// adds rejections across an existing estate and `Rejected` is
    /// terminal. A default that promoted would be a release deciding for
    /// an operator what D6 reserves to them.
    pub const fn composite_verdict_mode() -> CompositeVerdictMode {
        CompositeVerdictMode::Observed
    }
}

/// The **resolved** composite-verdict posture for the repository a
/// `policy` governs (ADR 0064 D6).
///
/// `None` — no operator policy resolved — is
/// [`CompositeVerdictMode::Observed`] via
/// [`DefaultPolicy::composite_verdict_mode`], because promotion is an
/// operator act against named criteria and the built-in default policy
/// has no operator behind it.
///
/// The single definition of the question, for the reason the two
/// verdict functions share [`Finding::may_condemn_artifact`]: the
/// posture decides whether a constituent's filesystem findings gate, and
/// whether the absence of a composite assessment holds a manifest, and
/// two sites resolving it separately could answer differently about one
/// repository. Mirrors `provenance_mode_of` in the application layer,
/// one axis over.
#[must_use]
pub fn composite_verdict_mode_of(policy: Option<&ScanPolicyProjection>) -> CompositeVerdictMode {
    policy
        .map(|p| p.composite_verdict_mode)
        .unwrap_or_else(DefaultPolicy::composite_verdict_mode)
}

/// Compute the quarantine observation-window **deadline** from the stored
/// immutable anchor and the resolved window duration (ADR 0007).
///
/// The deadline (`window_start + duration`) is **never persisted** — it
/// is a derived value computed from config (`ScanPolicy.quarantineDuration`,
/// or [`DefaultPolicy::quarantine_duration_secs`]) that can change after
/// an artifact is quarantined. Storing it would freeze a stale value;
/// the artifact stores only the anchor [`crate::entities::artifact::Artifact::quarantine_window_start`]
/// and every consumer (the release sweep's candidacy query, the
/// scan-completes-last fast path, and the proxy-`503` `Retry-After`
/// read path) computes the deadline through this one helper.
///
/// Pure addition — the helper does not clamp. Callers resolve a
/// non-negative `duration`; a negative duration is defined behaviour
/// (the deadline moves before the anchor) so the function stays total.
pub fn effective_quarantine_deadline(
    window_start: DateTime<Utc>,
    duration: chrono::Duration,
) -> DateTime<Utc> {
    window_start + duration
}

/// Composes the per-rule evaluators into a single [`ScanOutcome`].
///
/// `now` is the current wall-clock used by
/// [`filter_excluded_findings`] to evaluate exclusion expiry; passed
/// in explicitly so the domain layer remains time-source-free
/// (`Utc::now()` is forbidden inside `hort-domain`).
///
/// `policy` is `Option` because not every repository has a configured
/// policy. When `None`, [`DefaultPolicy::block_on_critical`] supplies
/// the threshold and the license-policy step is skipped entirely (no
/// policy → no license rules to apply).
///
/// `exclusions` is taken as a slice rather than collected against the
/// supplied `policy`'s id — the application layer is responsible for
/// fetching the right exclusion set for the resolved policy and
/// passing it in. An empty slice is the "no exclusions" case.
///
/// `kind` is what the artifact's own format handler says its bytes are
/// ([`FormatHandler::scan_kind`](crate::ports::format_handler::FormatHandler::scan_kind)),
/// and it is an assessment input beside `coords` rather than a field on
/// them: `coords` are request coordinates, and this is a property of the
/// payload. [`Finding::may_condemn_artifact`] spends it on ADR 0064 D2's
/// role half — whether a filesystem claim is about the filesystem this
/// artifact *is* or about one it is a constituent of. Every caller
/// resolves it through the handler registry, never from a path prefix,
/// which would be a second copy of `scan_kind`.
pub fn evaluate_scan_result(
    coords: &ArtifactCoords,
    kind: ArtifactKind,
    findings: &[Finding],
    policy: Option<&ScanPolicyProjection>,
    exclusions: &[ExclusionProjection],
    now: DateTime<Utc>,
) -> ScanOutcome {
    // Step 1 — drop findings matched by an active exclusion. The
    // post-exclusion `SeveritySummary` is computed from the survivors
    // inside the function (single source of truth — no aggregate
    // supplied by the caller). Exact CVE-ID matching against
    // `ExclusionProjection.cve_id`.
    let filtered = filter_excluded_findings(findings, exclusions, coords, now);

    // Step 1b — narrow the survivors to the findings that may decide THIS
    // artifact's verdict. A finding naming a component whose code the
    // artifact does not carry is real information about that component —
    // the payload resolved its coordinates out of a manifest or lockfile
    // it ships, and a consumer's build resolves none of those pins — but
    // it is not evidence about this artifact, so it has no authority over
    // this artifact's release gate (ADR 0056 as amended).
    //
    // It stays in the record. This function reads `findings` and writes
    // nothing, so the caller's list, the findings blob, the per-finding
    // rows and `ScanCompleted.severity_summary` are untouched; what is
    // narrowed is only the aggregate the thresholds are walked against —
    // the same present-but-non-enforcing split ADR 0040's negligible lane
    // already draws, reused rather than duplicated.
    //
    // Here, beside the exclusion filter, because both answer "which
    // findings may decide this verdict?" over the same input before any
    // threshold exists to walk — and the summary is recomputed from the
    // survivors for step 1's reason: no aggregate reaches the tier walk
    // that was not derived from the findings it governs. Both tier inputs
    // below (the walk and the negligible lane) read `condemning_summary`,
    // or a non-carried finding would still block through whichever one was
    // missed. Moving the vec out of `filtered` rather than copying it is
    // what makes reading the wider `filtered.remaining_findings` below a
    // compile error instead of a judgement call.
    //
    // `Finding::may_condemn_artifact` is the single definition of the
    // question; re-deriving it by matching on the relation — or on the
    // statement — here is what
    // `hort-app/tests/condemning_rule_is_single_sourced.rs` rejects.
    // `decide_rejected_transition` is its only other consumer and narrows
    // at the point this function does — the two verdict functions have to
    // agree about which findings may decide one finding list.
    //
    // The predicate asks a second question of the same input, and `kind`
    // plus the resolved composite-verdict posture are what it needs to
    // answer it: a finding about the filesystem one *constituent* of a
    // composition makes in isolation is evidence rather than the verdict
    // once an operator has promoted the composition's own verdict
    // (ADR 0064 D2). The posture is resolved here, from the policy this
    // evaluation is already under, so the narrowing and the posture cannot
    // come from different repositories; `kind` arrives from the caller,
    // which resolved it from the artifact's own format handler.
    //
    // This is the path a **fresh scan** takes, and also the **tighten**
    // re-evaluation over an artifact's stored findings. Both resolve the
    // posture rather than pinning it, which is what keeps them answering
    // one question: a constituent a promoted policy let through on a fresh
    // scan is not then re-rejected by the next threshold change.
    let composite_verdict = composite_verdict_mode_of(policy);
    let mut condemning = filtered.remaining_findings;
    condemning.retain(|f| f.may_condemn_artifact(kind, composite_verdict));
    let condemning_summary = severity_summary_from_findings(&condemning);

    // Step 2 — resolve threshold.
    let threshold = policy
        .map(|p| p.severity_threshold)
        .unwrap_or_else(DefaultPolicy::block_on_critical);

    // Step 3 — accumulate CVE-threshold violations with severity
    // escalation (each tier's own severity drives Allow → Warn → Block).
    let mut accumulator = ViolationsAccumulator::new();
    accumulator
        .collect_with_severity_escalation(evaluate_cve_thresholds(&condemning_summary, threshold));

    // Step 4 — license policy, only when a non-empty policy object was
    // supplied. `Value::Null` (the operator-left-the-field-unset
    // sentinel) and an empty JSON object both mean "no
    // license policy declared"; either way the accumulator gets no
    // license input. Anything richer (object with at least one entry)
    // dispatches to the license evaluator.
    if let Some(policy) = policy {
        if has_license_policy(&policy.license_policy) {
            // No SBOM port is wired here, so the license input is empty
            // and every rule in the policy matches nothing. That is why
            // a `licensePolicy` this branch would act on is refused at
            // apply (`has_license_policy` is the shared predicate): the
            // only projections that still reach here are rows stored
            // before that rule, which nothing rewrites. A non-empty list
            // becomes meaningful when a follow-on item surfaces SBOM
            // data through a port — at which point the apply-time
            // rejection goes away with it. The call still goes through
            // today so license-policy-shape violations (operator typos
            // in a stored row) surface even with zero licenses.
            let (license_violations, license_action) =
                evaluate_license_policy(&[], &policy.license_policy);
            accumulator.collect_with_policy_action(license_violations, license_action);
        }
    }

    // Step 4b — negligible / informational findings. The CVE tier-walk
    // never enforces the post-exclusion `negligible` count; this knob is
    // the only path that lets it influence the outcome. Exclusions ran
    // in Step 1, so an excluded informational finding is already gone
    // from `filtered.remaining` before this point. The same shared
    // helper drives the re-evaluation path so the two cannot diverge.
    let negligible_action = policy
        .map(|p| p.negligible_action)
        .unwrap_or_else(DefaultPolicy::negligible_action);
    collect_negligible_action(
        &mut accumulator,
        negligible_action,
        condemning_summary.negligible,
    );

    // Step 5 — translate accumulator outcome into ScanOutcome. The
    // enforcement mode selects between the two blocking-verdict
    // variants; it never suppresses a violation, so both carry the
    // identical `violations` list.
    let enforcement = policy
        .map(|p| p.enforcement)
        .unwrap_or_else(DefaultPolicy::enforcement);
    let (action, violations) = accumulator.into_outcome();
    match action {
        PolicyAction::Block => match enforcement {
            ScanEnforcement::Reject => ScanOutcome::Reject(violations),
            ScanEnforcement::Record => ScanOutcome::FindingsRecorded(violations),
        },
        // `Warn` and `Allow` are both Clean in either enforcement mode.
        // See module rustdoc — a `Warn` outcome with violations would
        // surface through `PolicyEvaluated(Pass, violations)` on a
        // future enhancement; today a non-blocking result is clean.
        PolicyAction::Warn | PolicyAction::Allow => ScanOutcome::Clean,
    }
}

/// Feeds the `negligible_action` enforcement step into a shared
/// [`ViolationsAccumulator`]. Single source of the negligible-lane
/// decision for both [`evaluate_scan_result`] (initial scan) and
/// [`crate::policy::decide_rejected_transition`] (exclusion-triggered
/// re-evaluation) so the two paths cannot diverge.
///
/// Keyed on the resolved `negligible_action`:
///   - `Ignore` → no-op (informational stays non-blocking);
///   - `Warn`   → one `negligible-advisory` violation, collected as
///     [`PolicyAction::Warn`] (recorded, non-blocking in the v1 scan
///     path);
///   - `Block`  → one `negligible-advisory` violation, collected as
///     [`PolicyAction::Block`] → the accumulator escalates to Block.
///
/// `negligible_count` is the post-exclusion negligible finding count;
/// a count of `0` returns immediately and adds nothing regardless of
/// the action.
pub(crate) fn collect_negligible_action(
    accumulator: &mut ViolationsAccumulator,
    negligible_action: NegligibleAction,
    negligible_count: u32,
) {
    if negligible_count == 0 {
        return;
    }
    let action = match negligible_action {
        NegligibleAction::Ignore => return,
        NegligibleAction::Warn => PolicyAction::Warn,
        NegligibleAction::Block => PolicyAction::Block,
    };
    let violation = PolicyViolation {
        rule: NEGLIGIBLE_RULE.to_string(),
        // Negligible is below the lowest enforceable tier; the
        // violation carries `Low` so it serialises cleanly and the
        // escalation comes from the policy action, not the severity.
        // (`SeverityThreshold` has no Negligible variant by design —
        // see `threshold.rs`.)
        severity: SeverityThreshold::Low,
        message: format!(
            "{negligible_count} informational/negligible advisory finding(s) under \
             negligibleAction = {negligible_action}"
        ),
        details: serde_json::json!({ "negligible_count": negligible_count }),
    };
    accumulator.collect_with_policy_action(vec![violation], action);
}

/// Returns true when `value` is a non-empty JSON object — i.e. there
/// is at least one operator-supplied license-policy field to evaluate.
/// `Value::Null` and `{}` both return false ("no license policy
/// declared"); other JSON kinds (array, string, number, bool) also
/// return true so the license evaluator surfaces a
/// `license-policy-shape` violation against the operator's malformed
/// input rather than silently swallowing it.
///
/// `pub` because this predicate is also the apply-time linter's
/// definition of a *declared* `licensePolicy`
/// (`hort_config::desired::validate_scan_policy_license_policy_not_implemented`):
/// a policy this function answers `true` for is one whose licence
/// decision the operator expects to be load-bearing, and no licence
/// input reaches [`evaluate_license_policy`] for it to decide on. The two
/// callers share the predicate rather than each carrying its own copy,
/// so the set the linter rejects cannot drift from the set that would
/// dispatch here.
pub fn has_license_policy(value: &serde_json::Value) -> bool {
    if value.is_null() {
        return false;
    }
    if let Some(obj) = value.as_object() {
        return !obj.is_empty();
    }
    // Non-null, non-object: surface the operator typo through the
    // license evaluator's shape-violation path.
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::repository::RepositoryFormat;
    use crate::entities::scan_policy::CompositeVerdictMode;
    use crate::entities::scan_policy::{
        ExclusionProjection, NegligibleAction, ProvenanceMode, ScanEnforcement,
    };
    use crate::events::PolicyScope;
    use crate::types::ComponentRelation;
    use chrono::TimeZone;
    use uuid::Uuid;

    /// The kind every test below evaluates under unless it is about the
    /// role half of ADR 0064 D2's line: a row that is **not** a
    /// composition constituent, so nothing in the statement axis can be
    /// what produced the outcome being asserted. The constituent cases
    /// name [`ArtifactKind::OciBlob`] literally.
    const TEST_KIND: ArtifactKind = ArtifactKind::NpmTarball;

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0)
            .single()
            .expect("fixed timestamp")
    }

    fn coords(name: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.to_string(),
            name_as_published: name.to_string(),
            version: Some("1.0.0".into()),
            path: format!("/{name}"),
            format: RepositoryFormat::Npm,
            metadata: serde_json::Value::Null,
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
            informational_class: None,
            severity_basis: crate::types::SeverityBasis::Assessed,
            component_relation: ComponentRelation::NotEstablished,
            statement: crate::types::FindingStatement::Unstated,
            advisory_published_at: None,
        }
    }

    /// An informational/negligible finding: no scored tier, classified
    /// informational by the advisory DB (the negligible-lane routing keys
    /// on `is_informational()`, derived from `informational_class`,
    /// regardless of the cosmetic `severity`).
    fn informational_finding(vuln: &str) -> Finding {
        Finding {
            informational_class: Some("unmaintained".to_string()),
            ..finding(vuln, SeverityThreshold::Low)
        }
    }

    /// Build a finding vec matching the legacy per-tier counts used by
    /// the previous aggregate-summary tests. Synthesises distinct CVE
    /// ids so the per-finding evaluator's exact-id matching is
    /// observable in test output.
    fn findings(critical: u32, high: u32, medium: u32, low: u32) -> Vec<Finding> {
        let mut out = Vec::new();
        for i in 0..critical {
            out.push(finding(&format!("CVE-C-{i}"), SeverityThreshold::Critical));
        }
        for i in 0..high {
            out.push(finding(&format!("CVE-H-{i}"), SeverityThreshold::High));
        }
        for i in 0..medium {
            out.push(finding(&format!("CVE-M-{i}"), SeverityThreshold::Medium));
        }
        for i in 0..low {
            out.push(finding(&format!("CVE-L-{i}"), SeverityThreshold::Low));
        }
        out
    }

    fn no_findings() -> Vec<Finding> {
        Vec::new()
    }

    fn projection(
        threshold: SeverityThreshold,
        license_policy: serde_json::Value,
    ) -> ScanPolicyProjection {
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
            license_policy,
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

    fn exclusion(
        id: u128,
        cve_id: &str,
        package_pattern: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> ExclusionProjection {
        ExclusionProjection {
            exclusion_id: Uuid::from_u128(id),
            policy_id: Uuid::from_u128(0xa11ce),
            cve_id: cve_id.to_string(),
            package_pattern: package_pattern.map(str::to_string),
            scope: PolicyScope::Global,
            reason: "test".into(),
            added_by_actor_id: None,
            expires_at,
        }
    }

    // ---- DefaultPolicy ----

    #[test]
    fn default_policy_blocks_on_critical_only() {
        assert_eq!(
            DefaultPolicy::block_on_critical(),
            SeverityThreshold::Critical
        );
    }

    // Out-of-the-box default backend list.
    #[test]
    fn default_policy_block_on_critical_default_backends_is_trivy() {
        // Out-of-the-box deployments scan with Trivy. The default is
        // load-bearing — Helm's `hort_svc_*` chart wires this through to
        // the `ScanOrchestrationConfig` via the unconfigured-policy
        // path in `ScanOrchestrationUseCase`.
        assert_eq!(
            DefaultPolicy::block_on_critical_default_backends(),
            vec!["trivy".to_string()]
        );
    }

    #[test]
    fn default_policy_block_on_critical_default_backends_returns_owned_vec() {
        // Each call yields a fresh Vec — callers are free to mutate
        // the result without observable interference. This guards
        // against accidentally returning a `&'static [String]` and
        // forcing every caller to clone.
        let mut v = DefaultPolicy::block_on_critical_default_backends();
        v.push("osv".into());
        // The next call still returns the unmodified default.
        assert_eq!(
            DefaultPolicy::block_on_critical_default_backends(),
            vec!["trivy".to_string()]
        );
    }

    // Out-of-the-box default rescan interval.
    #[test]
    fn default_policy_rescan_interval_hours_is_24() {
        // Out-of-the-box deployments rescan every 24 hours. The
        // constant is load-bearing — the YAML deserializer's default
        // and the SQL column DEFAULT both refer back to this value.
        assert_eq!(DefaultPolicy::rescan_interval_hours(), 24);
    }

    // Out-of-the-box default quarantine duration.
    #[test]
    fn default_policy_quarantine_duration_secs_is_86_400() {
        // Out-of-the-box deployments quarantine every fresh ingest for
        // 24 hours when no operator `ScanPolicy` is configured. The
        // constant is the source of truth for `ingest_inner`'s
        // matched-policy-absent fallback in `hort-app` and must stay
        // pinned — the pin doubles as a regression guard against an
        // accidental flip back to "permissive by default".
        assert_eq!(DefaultPolicy::quarantine_duration_secs(), 86_400);
    }

    // Out-of-the-box default negligible action.
    #[test]
    fn default_policy_negligible_action_is_ignore() {
        // The no-policy path treats informational/negligible findings as
        // non-blocking — matching the negligible tier's never-enforced
        // contract. A flip here would silently block on unmaintained deps.
        assert_eq!(DefaultPolicy::negligible_action(), NegligibleAction::Ignore);
    }

    // ---- effective_quarantine_deadline ----

    #[test]
    fn effective_quarantine_deadline_adds_duration_to_anchor() {
        // The deadline is `window_start + duration`, computed live, never stored.
        let anchor = ts(1_000_000);
        let deadline = effective_quarantine_deadline(anchor, chrono::Duration::hours(24));
        assert_eq!(deadline, ts(1_000_000 + 24 * 3600));
    }

    #[test]
    fn effective_quarantine_deadline_zero_duration_is_anchor() {
        // A zero observation window collapses the deadline onto the
        // anchor itself — the boundary case of permissive mode.
        let anchor = ts(2_000_000);
        assert_eq!(
            effective_quarantine_deadline(anchor, chrono::Duration::zero()),
            anchor
        );
    }

    #[test]
    fn effective_quarantine_deadline_negative_duration_moves_before_anchor() {
        // The helper is a pure addition — a negative duration moves the
        // deadline before the anchor. Defence-in-depth: callers resolve
        // a non-negative duration, but the helper does not clamp.
        let anchor = ts(3_000_000);
        assert_eq!(
            effective_quarantine_deadline(anchor, chrono::Duration::seconds(-100)),
            ts(3_000_000 - 100)
        );
    }

    // ---- has_license_policy helper ----

    #[test]
    fn has_license_policy_null_is_false() {
        assert!(!has_license_policy(&serde_json::Value::Null));
    }

    #[test]
    fn has_license_policy_empty_object_is_false() {
        assert!(!has_license_policy(&serde_json::json!({})));
    }

    #[test]
    fn has_license_policy_non_empty_object_is_true() {
        assert!(has_license_policy(&serde_json::json!({"action": "Block"})));
    }

    #[test]
    fn has_license_policy_array_is_true_to_surface_shape_violation() {
        // Non-null, non-object input is forwarded so the license
        // evaluator's shape-violation path fires.
        assert!(has_license_policy(&serde_json::json!(["GPL-3.0"])));
    }

    #[test]
    fn has_license_policy_string_is_true_to_surface_shape_violation() {
        assert!(has_license_policy(&serde_json::json!("not-a-policy")));
    }

    #[test]
    fn has_license_policy_bool_is_true_to_surface_shape_violation() {
        assert!(has_license_policy(&serde_json::json!(true)));
    }

    #[test]
    fn has_license_policy_number_is_true_to_surface_shape_violation() {
        assert!(has_license_policy(&serde_json::json!(42)));
    }

    // ---- evaluate_scan_result: clean paths ----

    #[test]
    fn no_findings_no_policy_returns_clean() {
        let r = evaluate_scan_result(
            &coords("anything"),
            TEST_KIND,
            &no_findings(),
            None,
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn no_findings_with_policy_returns_clean() {
        // Policy with all gates configured but zero findings → Clean.
        let policy = projection(
            SeverityThreshold::Low,
            serde_json::json!({
                "denied_licenses": ["GPL-3.0"],
                "action": "Block",
            }),
        );
        let r = evaluate_scan_result(
            &coords("anything"),
            TEST_KIND,
            &no_findings(),
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn high_finding_under_critical_threshold_returns_clean() {
        // The default threshold (Critical) lets `high` through.
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings(0, 5, 0, 0),
            None,
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn high_finding_under_explicit_critical_policy_returns_clean() {
        let policy = projection(SeverityThreshold::Critical, serde_json::Value::Null);
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings(0, 1, 0, 0),
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    // ---- evaluate_scan_result: CVE rejection ----

    #[test]
    fn critical_finding_no_policy_rejects_via_default() {
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings(1, 0, 0, 0),
            None,
            &[],
            ts(0),
        );
        match r {
            ScanOutcome::Reject(violations) => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].rule, super::super::cve::RULE);
                assert_eq!(violations[0].severity, SeverityThreshold::Critical);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn critical_finding_low_threshold_policy_rejects() {
        // Threshold = Low: every meaningful tier blocks — critical
        // certainly does.
        let policy = projection(SeverityThreshold::Low, serde_json::Value::Null);
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings(1, 0, 0, 0),
            Some(&policy),
            &[],
            ts(0),
        );
        match r {
            ScanOutcome::Reject(violations) => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].severity, SeverityThreshold::Critical);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn high_finding_high_threshold_rejects() {
        // High at threshold High → exceeds → Reject.
        let policy = projection(SeverityThreshold::High, serde_json::Value::Null);
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings(0, 1, 0, 0),
            Some(&policy),
            &[],
            ts(0),
        );
        match r {
            ScanOutcome::Reject(violations) => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].severity, SeverityThreshold::High);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // ---- evaluate_scan_result: exclusion ----

    #[test]
    fn critical_finding_with_matching_exclusion_returns_clean() {
        // Active exclusion drops the one critical finding by exact
        // CVE-id match.
        let critical = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-A", None, None)];
        let r = evaluate_scan_result(&coords("xz-utils"), TEST_KIND, &critical, None, &exs, ts(0));
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn critical_finding_with_expired_exclusion_rejects() {
        // Exclusion expired before `now` → no drop → Reject via
        // default threshold.
        let now = ts(2_000_000);
        let critical = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-A", None, Some(ts(1_000_000)))];
        let r = evaluate_scan_result(&coords("any"), TEST_KIND, &critical, None, &exs, now);
        match r {
            ScanOutcome::Reject(v) => assert_eq!(v.len(), 1),
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // ---- evaluate_scan_result: license policy ----

    #[test]
    fn license_shape_violation_alone_warns_so_returns_clean() {
        // The license evaluator emits a `license-policy-shape`
        // violation with PolicyAction::Warn for malformed top-level
        // JSON. `Warn` is not `Block` → ScanOutcome::Clean for v1.
        let policy = projection(
            SeverityThreshold::Critical,
            serde_json::json!("not-a-policy"),
        );
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &no_findings(),
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn license_block_action_alone_does_not_reject_when_no_violations() {
        // Empty license list (v1 — no SBOM port) means the license
        // evaluator produces zero violations regardless of the
        // configured Block action. Block escalation only fires when
        // there are violations to escalate
        // (see `collect_with_policy_action`); with no violations the
        // accumulator stays at Allow → ScanOutcome::Clean.
        let policy = projection(
            SeverityThreshold::Critical,
            serde_json::json!({
                "denied_licenses": ["GPL-3.0"],
                "action": "Block",
            }),
        );
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &no_findings(),
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn empty_license_policy_object_is_skipped_no_warn_violation() {
        // `Value::Null` and empty object both mean
        // "no license policy" and the license evaluator must not be
        // called. This guards against the `license::evaluate_license_policy`
        // empty-object path returning `(vec![], Warn)` and accidentally
        // shifting the scan accumulator off Allow.
        let policy = projection(SeverityThreshold::Critical, serde_json::json!({}));
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &no_findings(),
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    // ---- evaluate_scan_result: license + CVE composition ----

    #[test]
    fn license_shape_plus_critical_cve_returns_reject_with_both_violations() {
        // Critical CVE under the default-Critical threshold blocks.
        // The license shape violation fires alongside via Warn, but
        // its violation must still appear in the returned list.
        let policy = projection(
            SeverityThreshold::Critical,
            serde_json::json!("not-a-policy"),
        );
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings(1, 0, 0, 0),
            Some(&policy),
            &[],
            ts(0),
        );
        match r {
            ScanOutcome::Reject(violations) => {
                assert_eq!(violations.len(), 2);
                let rules: Vec<&str> = violations.iter().map(|v| v.rule.as_str()).collect();
                assert!(rules.contains(&super::super::cve::RULE));
                assert!(rules.contains(&super::super::license::RULE_SHAPE));
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // ---- evaluate_scan_result: negligible_action knob ----

    fn projection_with_negligible(action: NegligibleAction) -> ScanPolicyProjection {
        let mut p = projection(SeverityThreshold::High, serde_json::Value::Null);
        p.negligible_action = action;
        p
    }

    #[test]
    fn negligible_only_no_policy_is_clean_via_default_ignore() {
        // No policy → DefaultPolicy::negligible_action() == Ignore →
        // informational findings never block. This is exactly the
        // post-Part-A behaviour.
        let findings = vec![informational_finding("RUSTSEC-2026-0173")];
        let r = evaluate_scan_result(
            &coords("proc-macro-error2"),
            TEST_KIND,
            &findings,
            None,
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn negligible_only_ignore_policy_is_clean() {
        let policy = projection_with_negligible(NegligibleAction::Ignore);
        let findings = vec![informational_finding("RUSTSEC-2026-0173")];
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn negligible_only_warn_policy_is_clean_but_records_violation() {
        // Warn is recorded but non-blocking in the v1 binary scan path —
        // same shape as the license-shape Warn. The scan outcome is Clean
        // (a future enhancement surfaces it via PolicyEvaluated(Pass)).
        let policy = projection_with_negligible(NegligibleAction::Warn);
        let findings = vec![informational_finding("RUSTSEC-2026-0173")];
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn negligible_only_block_policy_rejects() {
        let policy = projection_with_negligible(NegligibleAction::Block);
        let findings = vec![informational_finding("RUSTSEC-2026-0173")];
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&policy),
            &[],
            ts(0),
        );
        match r {
            ScanOutcome::Reject(violations) => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].rule, NEGLIGIBLE_RULE);
                // The violation carries the negligible count in details.
                assert_eq!(violations[0].details["negligible_count"], 1);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn negligible_block_with_no_negligible_findings_is_clean() {
        // Block only fires when the post-exclusion negligible count > 0.
        // A scored-but-non-negligible finding under the threshold passes.
        let policy = projection_with_negligible(NegligibleAction::Block);
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings(0, 0, 0, 1),
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn scored_critical_rejects_regardless_of_negligible_ignore() {
        // Orthogonality: a scored Critical finding blocks under the
        // High threshold even when negligible_action = Ignore. The knob
        // does not relax the CVE gate.
        let policy = projection_with_negligible(NegligibleAction::Ignore);
        let findings = vec![
            finding("CVE-CRIT", SeverityThreshold::Critical),
            informational_finding("RUSTSEC-2026-0173"),
        ];
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&policy),
            &[],
            ts(0),
        );
        match r {
            ScanOutcome::Reject(violations) => {
                // The CVE violation fires; the Ignore'd negligible adds none.
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].rule, super::super::cve::RULE);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn scored_critical_and_negligible_block_yields_two_violations() {
        // A scored Critical AND a negligible finding under Block produce
        // both violations; the outcome is Reject either way.
        let policy = projection_with_negligible(NegligibleAction::Block);
        let findings = vec![
            finding("CVE-CRIT", SeverityThreshold::Critical),
            informational_finding("RUSTSEC-2026-0173"),
        ];
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&policy),
            &[],
            ts(0),
        );
        match r {
            ScanOutcome::Reject(violations) => {
                assert_eq!(violations.len(), 2);
                let rules: Vec<&str> = violations.iter().map(|v| v.rule.as_str()).collect();
                assert!(rules.contains(&super::super::cve::RULE));
                assert!(rules.contains(&NEGLIGIBLE_RULE));
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn excluded_negligible_finding_is_dropped_before_negligible_action() {
        // An exclusion drops the informational finding in Step 1, so the
        // post-exclusion negligible count is 0 and Block never fires.
        let policy = projection_with_negligible(NegligibleAction::Block);
        let findings = vec![informational_finding("RUSTSEC-2026-0173")];
        let exs = vec![exclusion(1, "RUSTSEC-2026-0173", None, None)];
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&policy),
            &exs,
            ts(0),
        );
        assert_eq!(
            r,
            ScanOutcome::Clean,
            "excluded informational finding must be gone before negligible_action is consulted"
        );
    }

    // ---- evaluate_scan_result: enforcement mode ----

    fn projection_with_enforcement(enforcement: ScanEnforcement) -> ScanPolicyProjection {
        let mut p = projection(SeverityThreshold::Critical, serde_json::Value::Null);
        p.enforcement = enforcement;
        p
    }

    #[test]
    fn default_policy_enforcement_is_reject() {
        // The no-policy path enforces. Non-enforcement is an explicit
        // operator declaration, never a fallback.
        assert_eq!(DefaultPolicy::enforcement(), ScanEnforcement::Reject);
    }

    #[test]
    fn blocking_verdict_under_record_returns_findings_recorded() {
        // Same critical finding that rejects under the default mode;
        // under `record` the verdict is computed and the violations are
        // returned for the audit trail, but the caller is told to record
        // rather than reject.
        let policy = projection_with_enforcement(ScanEnforcement::Record);
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings(1, 0, 0, 0),
            Some(&policy),
            &[],
            ts(0),
        );
        match r {
            ScanOutcome::FindingsRecorded(violations) => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].rule, super::super::cve::RULE);
                assert_eq!(violations[0].severity, SeverityThreshold::Critical);
            }
            other => panic!("expected FindingsRecorded, got {other:?}"),
        }
    }

    #[test]
    fn record_and_reject_produce_identical_violations() {
        // The enforcement knob must never change the *verdict* — only
        // what the caller does with it. Two evaluations over the same
        // findings under the two modes must carry byte-identical
        // violation lists, which is what makes the ADR 0041 tighten
        // direction re-derive the exact rejection the loosen direction
        // cleared.
        let findings = vec![
            finding("CVE-CRIT", SeverityThreshold::Critical),
            informational_finding("RUSTSEC-2026-0173"),
        ];
        let mut reject_policy = projection_with_enforcement(ScanEnforcement::Reject);
        reject_policy.negligible_action = NegligibleAction::Block;
        let mut record_policy = projection_with_enforcement(ScanEnforcement::Record);
        record_policy.negligible_action = NegligibleAction::Block;

        let rejected = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&reject_policy),
            &[],
            ts(0),
        );
        let recorded = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&record_policy),
            &[],
            ts(0),
        );
        match (rejected, recorded) {
            (ScanOutcome::Reject(a), ScanOutcome::FindingsRecorded(b)) => {
                assert_eq!(a, b, "record must not alter the computed violations");
                assert_eq!(a.len(), 2);
            }
            other => panic!("expected (Reject, FindingsRecorded), got {other:?}"),
        }
    }

    #[test]
    fn clean_verdict_under_record_is_still_clean() {
        // `record` only re-routes a BLOCK. A below-threshold result is
        // `Clean` in both modes — it must not be mislabelled as
        // "findings recorded" (which would report violations that never
        // fired).
        let policy = projection_with_enforcement(ScanEnforcement::Record);
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings(0, 1, 0, 0),
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn warn_only_verdict_under_record_is_clean_not_recorded() {
        // A `Warn`-escalated license-shape violation never reaches the
        // `Block` arm, so enforcement never sees it — Clean in both
        // modes.
        let mut policy = projection_with_enforcement(ScanEnforcement::Record);
        policy.license_policy = serde_json::json!("not-a-policy");
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &no_findings(),
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn excluded_finding_under_record_is_clean_not_recorded() {
        // Exclusions run BEFORE enforcement (step 1), so an excluded
        // finding produces no violation to record at all — the outcome
        // is Clean, not an empty `FindingsRecorded`.
        let policy = projection_with_enforcement(ScanEnforcement::Record);
        let critical = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-A", None, None)];
        let r = evaluate_scan_result(
            &coords("xz-utils"),
            TEST_KIND,
            &critical,
            Some(&policy),
            &exs,
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn negligible_block_under_record_returns_findings_recorded() {
        // The negligible lane composes with enforcement the same way the
        // scored lane does: `negligibleAction: block` computes a blocking
        // violation, `enforcement: record` records rather than rejects.
        let mut policy = projection_with_enforcement(ScanEnforcement::Record);
        policy.negligible_action = NegligibleAction::Block;
        let findings = vec![informational_finding("RUSTSEC-2026-0173")];
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&policy),
            &[],
            ts(0),
        );
        match r {
            ScanOutcome::FindingsRecorded(violations) => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].rule, NEGLIGIBLE_RULE);
            }
            other => panic!("expected FindingsRecorded, got {other:?}"),
        }
    }

    #[test]
    fn explicit_reject_enforcement_matches_absent_policy_behaviour() {
        // Zero-migration guarantee: `enforcement: reject` (the default a
        // missing YAML field parses to) is exactly today's behaviour.
        let policy = projection_with_enforcement(ScanEnforcement::Reject);
        let with_policy = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings(1, 0, 0, 0),
            Some(&policy),
            &[],
            ts(0),
        );
        let no_policy = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings(1, 0, 0, 0),
            None,
            &[],
            ts(0),
        );
        assert!(matches!(with_policy, ScanOutcome::Reject(_)));
        assert!(matches!(no_policy, ScanOutcome::Reject(_)));
    }

    // ---- evaluate_scan_result: which findings may condemn ----
    //
    // The regression these pin matters more than the narrowing itself:
    // an over-broad predicate disarms the scanner silently, because every
    // test that only checks "the bad artifact was rejected for the right
    // reason" keeps passing on the cases it still catches. So the
    // subject-still-condemns direction comes first, and
    // `every_relation_that_may_condemn_still_rejects` sweeps the whole
    // enum against the predicate rather than naming one relation.

    /// `finding`, re-tagged with the relation under test — the only thing
    /// that differs between the cases below.
    fn about(relation: ComponentRelation, mut f: Finding) -> Finding {
        f.component_relation = relation;
        f
    }

    /// §4, first: a finding about the artifact's **own** subject component
    /// condemns exactly as before. This is the case the narrowing must not
    /// touch, and an over-broad predicate would fail here and nowhere
    /// else obvious.
    #[test]
    fn a_subject_component_finding_over_the_threshold_still_rejects() {
        let findings = vec![about(
            ComponentRelation::Subject,
            finding("CVE-SUBJECT", SeverityThreshold::Critical),
        )];
        let r = evaluate_scan_result(
            &coords("hyper-util"),
            TEST_KIND,
            &findings,
            None,
            &[],
            ts(0),
        );
        assert!(
            matches!(r, ScanOutcome::Reject(_)),
            "a finding about the artifact itself keeps full release authority, got {r:?}",
        );
    }

    /// §4, fourth: a format whose payload carries its closure — an OCI
    /// image and its layers. The component is not the subject and the code
    /// *is* in the artifact, so it condemns unchanged. Collapsing this
    /// into the subject case would disarm every layer finding on every
    /// image.
    #[test]
    fn a_contained_component_finding_over_the_threshold_still_rejects() {
        let findings = vec![about(
            ComponentRelation::Contained,
            finding("CVE-LAYER", SeverityThreshold::Critical),
        )];
        let r = evaluate_scan_result(&coords("app"), TEST_KIND, &findings, None, &[], ts(0));
        assert!(matches!(r, ScanOutcome::Reject(_)), "{r:?}");
    }

    /// §4, third: an unestablished relation condemns. A record whose
    /// relation was never established — every finding persisted before the
    /// field existed — must keep today's behaviour; defaulting the other
    /// way would disarm the whole stored corpus in one step (ADR 0007).
    #[test]
    fn a_not_established_relation_over_the_threshold_still_rejects() {
        let findings = vec![about(
            ComponentRelation::NotEstablished,
            finding("CVE-LEGACY", SeverityThreshold::Critical),
        )];
        let r = evaluate_scan_result(&coords("any"), TEST_KIND, &findings, None, &[], ts(0));
        assert!(matches!(r, ScanOutcome::Reject(_)), "{r:?}");
    }

    /// The narrowing itself (§4, second) — and the half that keeps it
    /// honest. A finding naming a component the artifact does not carry no
    /// longer blocks, AND it is still in the caller's list and still
    /// counted by the aggregate the `ScanCompleted` event carries.
    /// Implementing the rule as a removal from the record would trade one
    /// wrong answer for another.
    #[test]
    fn a_not_contained_component_finding_no_longer_rejects_and_stays_in_the_record() {
        let findings = vec![about(
            ComponentRelation::NotContained,
            finding("CVE-ELSEWHERE", SeverityThreshold::Critical),
        )];
        let r = evaluate_scan_result(&coords("any"), TEST_KIND, &findings, None, &[], ts(0));
        assert_eq!(
            r,
            ScanOutcome::Clean,
            "a component the artifact does not carry has no authority over its release",
        );

        assert_eq!(findings.len(), 1, "the evaluator removes nothing");
        assert_eq!(
            severity_summary_from_findings(&findings).critical,
            1,
            "the recorded aggregate still counts it; only its authority changed",
        );
    }

    /// The incident this change exists for, through the evaluator. A cargo
    /// `.crate` ships the maintainer's `Cargo.lock` and none of the code it
    /// pins, so the advisory against the pinned `h2` names code the
    /// artifact does not contain — and `hyper-util 0.1.21` was terminally
    /// rejected over it.
    #[test]
    fn a_lockfile_pin_no_longer_rejects_the_crate_that_ships_none_of_it() {
        let mut pinned = about(
            ComponentRelation::NotContained,
            finding("RUSTSEC-2026-0004", SeverityThreshold::Critical),
        );
        pinned.purl = "pkg:cargo/h2@0.4.13".into();
        let r = evaluate_scan_result(
            &coords("hyper-util"),
            TEST_KIND,
            &[pinned],
            None,
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    /// The narrowing is per finding, not per scan: one non-carried
    /// component alongside a real subject finding must not carry the
    /// subject's rejection away with it.
    #[test]
    fn a_subject_finding_still_rejects_beside_a_non_contained_one() {
        let findings = vec![
            about(
                ComponentRelation::NotContained,
                finding("CVE-ELSEWHERE", SeverityThreshold::Critical),
            ),
            about(
                ComponentRelation::Subject,
                finding("CVE-HERE", SeverityThreshold::Critical),
            ),
        ];
        let r = evaluate_scan_result(&coords("any"), TEST_KIND, &findings, None, &[], ts(0));
        match r {
            ScanOutcome::Reject(violations) => assert_eq!(
                violations.len(),
                1,
                "exactly the one condemning critical, not two: {violations:?}",
            ),
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    /// The evaluator's verdict follows the predicate for every relation —
    /// which is what catches a filter here that narrows on its own terms
    /// rather than by asking. Expectations come from
    /// `Finding::may_condemn_artifact` itself, so a future relation is
    /// swept without an edit; the price is that it says nothing about the
    /// predicate's own arms (a change there moves both sides at once).
    /// Those arms are pinned in `types::finding`, and the four cases
    /// above name their relations literally for exactly this reason.
    #[test]
    fn every_relation_that_may_condemn_still_rejects() {
        for relation in [
            ComponentRelation::Subject,
            ComponentRelation::Contained,
            ComponentRelation::NotContained,
            ComponentRelation::NotEstablished,
        ] {
            let one = about(relation, finding("CVE-SWEEP", SeverityThreshold::Critical));
            let condemns = one.may_condemn_artifact(TEST_KIND, CompositeVerdictMode::Observed);
            let r = evaluate_scan_result(&coords("any"), TEST_KIND, &[one], None, &[], ts(0));
            assert_eq!(
                matches!(r, ScanOutcome::Reject(_)),
                condemns,
                "{relation:?}: the verdict must follow the predicate, got {r:?}",
            );
        }
    }

    /// The negligible lane reads the narrowed aggregate too. An
    /// informational advisory about a component the artifact does not
    /// carry cannot block under `negligibleAction: block` — otherwise the
    /// rule would hold on the scored lane and leak on the lane beside it.
    #[test]
    fn a_non_contained_informational_finding_cannot_block_the_negligible_lane() {
        let mut policy = projection(SeverityThreshold::Critical, serde_json::Value::Null);
        policy.negligible_action = NegligibleAction::Block;
        let findings = vec![about(
            ComponentRelation::NotContained,
            informational_finding("RUSTSEC-2026-0173"),
        )];
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean, "{r:?}");
    }

    /// The other direction of the same lane: an informational advisory
    /// whose relation was never established still blocks under
    /// `negligibleAction: block`, exactly as before.
    #[test]
    fn a_not_established_informational_finding_still_blocks_the_negligible_lane() {
        let mut policy = projection(SeverityThreshold::Critical, serde_json::Value::Null);
        policy.negligible_action = NegligibleAction::Block;
        let findings = vec![about(
            ComponentRelation::NotEstablished,
            informational_finding("RUSTSEC-2026-0173"),
        )];
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&policy),
            &[],
            ts(0),
        );
        match r {
            ScanOutcome::Reject(violations) => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].rule, NEGLIGIBLE_RULE);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // -- the statement axis (ADR 0064 D2) ----------------------------------

    /// A stored finding as the Trivy adapter produced it from a
    /// `Vulnerabilities` entry: a claim about the filesystem the
    /// materialised bytes compose into. Whose filesystem that is, the
    /// producer does not say — the row's kind decides, which is what
    /// these tests vary.
    fn filesystem_finding(vuln: &str, sev: SeverityThreshold) -> Finding {
        let mut f = finding(vuln, sev);
        f.statement = crate::types::FindingStatement::Filesystem;
        f
    }

    /// A promoted policy at `threshold`.
    fn promoted(threshold: SeverityThreshold) -> ScanPolicyProjection {
        ScanPolicyProjection {
            composite_verdict_mode: CompositeVerdictMode::Promoted,
            ..projection(threshold, serde_json::Value::Null)
        }
    }

    /// **The trapdoor, closed.** A constituent cleared by a fresh scan
    /// under a promoted policy is still clear when an operator *lowers* a
    /// threshold and the tighten pass re-derives the verdict over the
    /// same **stored** findings.
    ///
    /// Both halves run through this one function, because the tighten
    /// pass is this function over the stored findings blob — so the only
    /// thing that differs between them is the threshold the operator
    /// moved. While the statement was transient the second half rejected:
    /// a hydrated finding read `Unstated`, which condemns, and
    /// `ScanPolicyRetroactive → Rejected` is revisited by no rescan. The
    /// finding is serialised and read back here rather than reused by
    /// value, because "it survives the blob" is the half that was broken.
    #[test]
    fn a_threshold_tighten_does_not_re_reject_a_promoted_constituent() {
        let fresh = vec![filesystem_finding(
            "CVE-2022-LAYER",
            SeverityThreshold::High,
        )];
        assert_eq!(
            evaluate_scan_result(
                &coords("layer"),
                ArtifactKind::OciBlob,
                &fresh,
                Some(&promoted(SeverityThreshold::Critical)),
                &[],
                ts(0),
            ),
            ScanOutcome::Clean,
            "the fresh scan under a promoted policy lets the layer through: \
             the composition that binds it carries the filesystem verdict",
        );

        // What the tighten pass actually reads: the stored findings blob.
        let blob = serde_json::to_string(&fresh).unwrap();
        let stored: Vec<Finding> = serde_json::from_str(&blob).unwrap();

        assert_eq!(
            evaluate_scan_result(
                &coords("layer"),
                ArtifactKind::OciBlob,
                &stored,
                Some(&promoted(SeverityThreshold::High)),
                &[],
                ts(0),
            ),
            ScanOutcome::Clean,
            "lowering the threshold must not terminally reject the layer the \
             same policy just released — the verdict re-taken over stored \
             findings has to read the same fact the fresh scan read",
        );
    }

    /// And the counter-case that says the test above is not vacuous: the
    /// identical stored findings, at the identical lowered threshold,
    /// reject under the default posture. The tighten pass is doing real
    /// work; what changed is only that it now reads the statement.
    #[test]
    fn the_same_tighten_still_rejects_an_unpromoted_constituent() {
        let fresh = vec![filesystem_finding(
            "CVE-2022-LAYER",
            SeverityThreshold::High,
        )];
        let blob = serde_json::to_string(&fresh).unwrap();
        let stored: Vec<Finding> = serde_json::from_str(&blob).unwrap();
        let r = evaluate_scan_result(
            &coords("layer"),
            ArtifactKind::OciBlob,
            &stored,
            Some(&projection(
                SeverityThreshold::High,
                serde_json::Value::Null,
            )),
            &[],
            ts(0),
        );
        assert!(
            matches!(r, ScanOutcome::Reject(_)),
            "an unpromoted constituent gates on its own filesystem findings \
             exactly as it did before ADR 0064 D2: {r:?}",
        );
    }

    /// A promoted policy is **not** a global disarm: the same stored
    /// filesystem finding at the same lowered threshold still rejects
    /// every row whose materialised tree is its own. `compositeVerdictMode`
    /// is a `ScanPolicy` field and a global policy reaches every
    /// repository, so this is the assertion that keeps an operator
    /// promoting their OCI estate from disarming their npm one.
    #[test]
    fn promotion_does_not_disarm_a_row_whose_filesystem_is_its_own() {
        let stored = vec![filesystem_finding("CVE-2022-TREE", SeverityThreshold::High)];
        for kind in [
            ArtifactKind::OciManifest,
            ArtifactKind::NpmTarball,
            ArtifactKind::CargoCrate,
            ArtifactKind::PyWheel,
            ArtifactKind::PySdist,
            ArtifactKind::MavenJar,
            ArtifactKind::MavenPom,
            ArtifactKind::Other,
        ] {
            let r = evaluate_scan_result(
                &coords("pkg"),
                kind,
                &stored,
                Some(&promoted(SeverityThreshold::High)),
                &[],
                ts(0),
            );
            assert!(
                matches!(r, ScanOutcome::Reject(_)),
                "{kind}: the materialised tree is this artifact's own, so a \
                 promoted composite verdict has nothing to move the claim to: {r:?}",
            );
        }
    }

    /// A non-carried finding produces no violation at all, so under
    /// `enforcement: record` the verdict is `Clean` rather than an empty
    /// `FindingsRecorded` — the same shape an excluded finding already
    /// takes. An operator reading a recorded verdict must be looking at
    /// something that was actually computed against this artifact.
    #[test]
    fn a_non_contained_finding_under_record_enforcement_is_clean_not_recorded() {
        let policy = projection_with_enforcement(ScanEnforcement::Record);
        let findings = vec![about(
            ComponentRelation::NotContained,
            finding("CVE-ELSEWHERE", SeverityThreshold::Critical),
        )];
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    /// The narrowing is independent of the threshold: lowering the
    /// operator's threshold to the finding's own tier does not give a
    /// non-carried component authority back.
    #[test]
    fn a_non_contained_finding_does_not_block_at_its_own_threshold() {
        let policy = projection(SeverityThreshold::Low, serde_json::Value::Null);
        let findings = vec![about(
            ComponentRelation::NotContained,
            finding("CVE-LOW", SeverityThreshold::Low),
        )];
        let r = evaluate_scan_result(
            &coords("any"),
            TEST_KIND,
            &findings,
            Some(&policy),
            &[],
            ts(0),
        );
        assert_eq!(r, ScanOutcome::Clean);
    }

    /// The two filters compose, in either order: an exclusion clearing the
    /// one condemning finding leaves a non-carried one that cannot block,
    /// so the artifact comes out clean rather than held by the leftover.
    #[test]
    fn an_exclusion_and_the_relation_filter_compose() {
        let findings = vec![
            about(
                ComponentRelation::Subject,
                finding("CVE-HERE", SeverityThreshold::Critical),
            ),
            about(
                ComponentRelation::NotContained,
                finding("CVE-ELSEWHERE", SeverityThreshold::Critical),
            ),
        ];
        let exs = vec![exclusion(7, "CVE-HERE", None, None)];
        let r = evaluate_scan_result(&coords("any"), TEST_KIND, &findings, None, &exs, ts(0));
        assert_eq!(r, ScanOutcome::Clean, "{r:?}");
    }

    // ---- ScanOutcome derives ----

    #[test]
    fn scan_outcome_clone_eq() {
        let a = ScanOutcome::Clean;
        let b = a.clone();
        assert_eq!(a, b);

        let viol = PolicyViolation {
            rule: "test".into(),
            severity: SeverityThreshold::Critical,
            message: "msg".into(),
            details: serde_json::Value::Null,
        };
        let r1 = ScanOutcome::Reject(vec![viol.clone()]);
        let r2 = ScanOutcome::Reject(vec![viol]);
        assert_eq!(r1, r2);

        assert_ne!(ScanOutcome::Clean, ScanOutcome::Reject(vec![]));
        // `FindingsRecorded` is a DISTINCT verdict from both — a caller
        // matching on `Reject` must never see a recorded outcome and
        // vice versa.
        assert_ne!(
            ScanOutcome::Reject(vec![]),
            ScanOutcome::FindingsRecorded(vec![])
        );
        assert_ne!(ScanOutcome::Clean, ScanOutcome::FindingsRecorded(vec![]));
    }

    #[test]
    fn scan_outcome_debug_formats() {
        // Defence-in-depth: derive(Debug) must compile and produce
        // non-empty output for every variant.
        let s = format!("{:?}", ScanOutcome::Clean);
        assert!(s.contains("Clean"));
        let s = format!("{:?}", ScanOutcome::Reject(vec![]));
        assert!(s.contains("Reject"));
        let s = format!("{:?}", ScanOutcome::FindingsRecorded(vec![]));
        assert!(s.contains("FindingsRecorded"));
    }
}
