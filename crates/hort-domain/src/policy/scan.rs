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
//!    `(action, violations)`. `Block` → [`ScanOutcome::Reject`];
//!    anything else → [`ScanOutcome::Clean`]. `Warn` outcomes do not
//!    block in the scan path — the v1 scan result is binary
//!    (clean or rejected); `Warn` violations would surface as
//!    [`crate::events::PolicyEvaluated`] entries on a future
//!    enhancement but do not affect quarantine state today.
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

use crate::entities::scan_policy::{ExclusionProjection, ScanPolicyProjection, SeverityThreshold};
use crate::events::PolicyViolation;
use crate::types::{ArtifactCoords, Finding};

use super::cve::evaluate_cve_thresholds;
use super::exclusion::filter_excluded_findings;
use super::license::evaluate_license_policy;
use super::primitives::{PolicyAction, ViolationsAccumulator};

/// Outcome of evaluating a scan result against the active policy.
///
/// Binary by design in v1 — the `QuarantineUseCase::record_scan_result`
/// path emits either a clean [`crate::events::ScanCompleted`] or the
/// reject triple (`ScanCompleted` + `PolicyEvaluated(Fail)` +
/// `ArtifactRejected`). Future enhancements that surface `Warn`
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
    /// blocks. Caller emits `PolicyEvaluated(Fail, violations)` +
    /// `ArtifactRejected`.
    Reject(Vec<PolicyViolation>),
}

/// Default-policy fallback used when the artifact's repository has no
/// active policy resolved. Lives next to [`evaluate_scan_result`] for
/// now — promote to a shared module if Item 8 (curation gate) needs
/// it too.
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
    /// via [`effective_quarantine_deadline`] (§2.5 — anchor is
    /// persisted, deadline is never persisted).
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
pub fn evaluate_scan_result(
    coords: &ArtifactCoords,
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

    // Step 2 — resolve threshold.
    let threshold = policy
        .map(|p| p.severity_threshold)
        .unwrap_or_else(DefaultPolicy::block_on_critical);

    // Step 3 — accumulate CVE-threshold violations with severity
    // escalation (each tier's own severity drives Allow → Warn → Block).
    let mut accumulator = ViolationsAccumulator::new();
    accumulator
        .collect_with_severity_escalation(evaluate_cve_thresholds(&filtered.remaining, threshold));

    // Step 4 — license policy, only when a non-empty policy object was
    // supplied. `Value::Null` (the operator-left-the-field-unset
    // sentinel) and an empty JSON object both mean "no
    // license policy declared"; either way the accumulator gets no
    // license input. Anything richer (object with at least one entry)
    // dispatches to the license evaluator.
    if let Some(policy) = policy {
        if has_license_policy(&policy.license_policy) {
            // v1: no SBOM port wired here, so license input is empty.
            // A non-empty list becomes meaningful when a follow-on item
            // surfaces SBOM data through a port; the call still goes
            // through today so license-policy-shape violations
            // (operator typos in YAML) surface even with zero licenses.
            let (license_violations, license_action) =
                evaluate_license_policy(&[], &policy.license_policy);
            accumulator.collect_with_policy_action(license_violations, license_action);
        }
    }

    // Step 5 — translate accumulator outcome into ScanOutcome.
    let (action, violations) = accumulator.into_outcome();
    match action {
        PolicyAction::Block => ScanOutcome::Reject(violations),
        // `Warn` and `Allow` are both Clean for the v1 scan path. See
        // module rustdoc — a `Warn` outcome with violations would
        // surface through `PolicyEvaluated(Pass, violations)` on a
        // future enhancement; today the scan-result path is binary.
        PolicyAction::Warn | PolicyAction::Allow => ScanOutcome::Clean,
    }
}

/// Returns true when `value` is a non-empty JSON object — i.e. there
/// is at least one operator-supplied license-policy field to evaluate.
/// `Value::Null` and `{}` both return false ("no license policy
/// declared"); other JSON kinds (array, string, number, bool) also
/// return true so the license evaluator surfaces a
/// `license-policy-shape` violation against the operator's malformed
/// input rather than silently swallowing it.
fn has_license_policy(value: &serde_json::Value) -> bool {
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
    use crate::entities::scan_policy::{ExclusionProjection, ProvenanceMode};
    use crate::events::PolicyScope;
    use chrono::TimeZone;
    use uuid::Uuid;

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

    // ---- effective_quarantine_deadline ----

    #[test]
    fn effective_quarantine_deadline_adds_duration_to_anchor() {
        // §2.5 — the deadline is `window_start + duration`, computed
        // live, never stored.
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
        let r = evaluate_scan_result(&coords("anything"), &no_findings(), None, &[], ts(0));
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
        let r = evaluate_scan_result(&coords("any"), &findings(0, 5, 0, 0), None, &[], ts(0));
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn high_finding_under_explicit_critical_policy_returns_clean() {
        let policy = projection(SeverityThreshold::Critical, serde_json::Value::Null);
        let r = evaluate_scan_result(
            &coords("any"),
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
        let r = evaluate_scan_result(&coords("any"), &findings(1, 0, 0, 0), None, &[], ts(0));
        match r {
            ScanOutcome::Reject(violations) => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].rule, super::super::cve::RULE);
                assert_eq!(violations[0].severity, SeverityThreshold::Critical);
            }
            ScanOutcome::Clean => panic!("expected Reject"),
        }
    }

    #[test]
    fn critical_finding_low_threshold_policy_rejects() {
        // Threshold = Low: every meaningful tier blocks — critical
        // certainly does.
        let policy = projection(SeverityThreshold::Low, serde_json::Value::Null);
        let r = evaluate_scan_result(
            &coords("any"),
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
            ScanOutcome::Clean => panic!("expected Reject"),
        }
    }

    #[test]
    fn high_finding_high_threshold_rejects() {
        // High at threshold High → exceeds → Reject.
        let policy = projection(SeverityThreshold::High, serde_json::Value::Null);
        let r = evaluate_scan_result(
            &coords("any"),
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
            ScanOutcome::Clean => panic!("expected Reject"),
        }
    }

    // ---- evaluate_scan_result: exclusion ----

    #[test]
    fn critical_finding_with_matching_exclusion_returns_clean() {
        // Active exclusion drops the one critical finding by exact
        // CVE-id match.
        let critical = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-A", None, None)];
        let r = evaluate_scan_result(&coords("xz-utils"), &critical, None, &exs, ts(0));
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn critical_finding_with_expired_exclusion_rejects() {
        // Exclusion expired before `now` → no drop → Reject via
        // default threshold.
        let now = ts(2_000_000);
        let critical = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-A", None, Some(ts(1_000_000)))];
        let r = evaluate_scan_result(&coords("any"), &critical, None, &exs, now);
        match r {
            ScanOutcome::Reject(v) => assert_eq!(v.len(), 1),
            ScanOutcome::Clean => panic!("expected Reject"),
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
        let r = evaluate_scan_result(&coords("any"), &no_findings(), Some(&policy), &[], ts(0));
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
        let r = evaluate_scan_result(&coords("any"), &no_findings(), Some(&policy), &[], ts(0));
        assert_eq!(r, ScanOutcome::Clean);
    }

    #[test]
    fn empty_license_policy_object_is_skipped_no_warn_violation() {
        // Per backlog: `Value::Null` and empty object both mean
        // "no license policy" and the license evaluator must not be
        // called. This guards against the `license::evaluate_license_policy`
        // empty-object path returning `(vec![], Warn)` and accidentally
        // shifting the scan accumulator off Allow.
        let policy = projection(SeverityThreshold::Critical, serde_json::json!({}));
        let r = evaluate_scan_result(&coords("any"), &no_findings(), Some(&policy), &[], ts(0));
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
            ScanOutcome::Clean => panic!("expected Reject"),
        }
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
    }

    #[test]
    fn scan_outcome_debug_formats() {
        // Defence-in-depth: derive(Debug) must compile and produce
        // non-empty output for both variants.
        let s = format!("{:?}", ScanOutcome::Clean);
        assert!(s.contains("Clean"));
        let s = format!("{:?}", ScanOutcome::Reject(vec![]));
        assert!(s.contains("Reject"));
    }
}
