//! Promotion-gate decision point.
//!
//! Pure helper that evaluates the active scan
//! policy against a `Released` artifact's most recent scan summary and
//! decides what action the promotion path should take.
//!
//! Pure domain — zero I/O, zero `tracing`. The application caller
//! ([`PromotionUseCase::evaluate_and_promote`](crate)) is responsible
//! for resolving the active policy + exclusion set + last scan summary
//! via outbound ports, then translating the [`PromotionOutcome`] into
//! emitted events.
//!
//! ## v1 simplification (CVE-only)
//!
//! License / age / signature
//! checks are NOT wired here in v1. The evaluator consults only the
//! aggregate [`SeveritySummary`] (the artifact's most recent
//! `ScanCompleted` payload) and the active exclusion set. The other
//! gates ride along when their ports ship — see the TODO below.
//!
//! ```text
//! TODO(promotion-gate-followon): wire CveSummary / LicenseSummary ports
//! when scanner integration ships.
//! ```
//!
//! Open follow-on (see the open-items register in ADR 0000): wire
//! the CveSummary / LicenseSummary ports; signature checking is
//! covered by the provenance release gate (ADR 0027), not a
//! promotion-gate port.
//!
//! Until those ports land, the artifact passes the promotion gate as
//! soon as no excluded-and-thresholded CVE remains. License-policy
//! shape violations stored on `ScanPolicyProjection.license_policy`
//! still surface through the scan-result path at scan time;
//! a clean promotion attempt does not need to re-check them.
//!
//! ## Outcome derivation
//!
//! 1. CVE check: [`filter_excluded_findings`] + [`evaluate_cve_thresholds`]
//!    → produces 0..N [`PolicyViolation`]s with per-tier severity.
//! 2. [`ViolationsAccumulator::collect_with_severity_escalation`]
//!    yields the running [`PolicyAction`] (Allow / Warn / Block).
//! 3. Translate `(action, violations)` into a [`PromotionOutcome`]:
//!
//! | accumulator action | policy.require_approval | outcome |
//! |--------------------|-------------------------|---------|
//! | `Block`            | any                     | `Reject(violations)` |
//! | `Warn`             | any                     | `Warn(violations)` |
//! | `Allow`            | `true`                  | `RequireApproval(violations)` (violations may be empty) |
//! | `Allow`            | `false`                 | `Allow` |
//! | `Allow`            | n/a (`policy == None`)  | `Allow` (no policy = no approval requirement) |
//!
//! ## Missing-scan-summary fast path
//!
//! When the artifact has never been scanned, `last_scan_summary` is
//! [`None`]. The evaluator treats that as a clean baseline (zero
//! findings) — the artifact passes the CVE check and the outcome
//! falls out of the same translator. A missing scan summary (artifact
//! never scanned) treats CVE input as empty/clean.
//!
//! This is intentional. v1 does not require a scan to have run before
//! promotion. When scanner integration
//! ships and "every artifact must be scanned before promotion" becomes
//! a deployment policy, that gate lives in the use-case layer (refuse
//! to promote without a recent scan) — not here.

use chrono::{DateTime, Utc};

use crate::entities::artifact::Artifact;
use crate::entities::repository::Repository;
use crate::entities::scan_policy::{ExclusionProjection, ScanPolicyProjection};
use crate::events::{PolicyViolation, SeveritySummary};
use crate::types::ArtifactCoords;

use super::cve::evaluate_cve_thresholds;
use super::exclusion::filter_excluded_summary;
use super::primitives::{PolicyAction, ViolationsAccumulator};
use super::scan::DefaultPolicy;

/// Outcome of [`evaluate_promotion`].
///
/// `Allow` is the success-clean path. `Warn` promotes the artifact but
/// records non-blocking violations alongside the
/// [`PolicyEvaluated`](crate::events::PolicyEvaluated) audit event.
/// `RequireApproval` blocks the automatic promotion and emits an
/// [`ApprovalRequested`](crate::events::ApprovalRequested) waiting for
/// a human reviewer (see
/// [`PromotionUseCase::decide_approval`](crate)). `Reject` blocks the
/// promotion outright and emits a
/// [`PromotionRejected`](crate::events::PromotionRejected).
///
/// Not [`serde::Serialize`] — domain outcome enum, not an event
/// payload. The `Vec<PolicyViolation>` carried here flows into the
/// [`PolicyEvaluated.violations`](crate::events::PolicyEvaluated::violations)
/// field at the calling site.
#[derive(Debug, Clone, PartialEq)]
pub enum PromotionOutcome {
    /// CVE gate passed and no approval required. Caller emits
    /// `PolicyEvaluated(Pass, []) + ArtifactPromoted`.
    Allow,
    /// CVE gate produced warnings (non-blocking violations). Caller
    /// emits `PolicyEvaluated(Pass, violations) + ArtifactPromoted`.
    Warn(Vec<PolicyViolation>),
    /// CVE gate passed (or warned) and the active policy demands
    /// manual approval. Caller emits
    /// `PolicyEvaluated(Pass, violations) + ApprovalRequested`. The
    /// `Vec<PolicyViolation>` may be empty when a clean artifact still
    /// requires approval purely because of `require_approval = true`.
    RequireApproval(Vec<PolicyViolation>),
    /// CVE gate produced blocking violations. Caller emits
    /// `PolicyEvaluated(Fail, violations) + PromotionRejected`.
    Reject(Vec<PolicyViolation>),
}

/// Composes the per-rule evaluators into a single
/// [`PromotionOutcome`].
///
/// `now` is the current wall-clock used by
/// [`filter_excluded_findings`] to evaluate exclusion expiry; passed
/// in explicitly so the domain layer remains time-source-free.
///
/// `policy` is `Option` because not every repository has a configured
/// policy. When `None`, [`DefaultPolicy::block_on_critical`] supplies
/// the threshold and `require_approval` is treated as `false` (no
/// policy → no approval requirement).
///
/// `last_scan_summary` is `Option` because not every artifact has
/// been scanned. When `None`, the evaluator treats CVE input as empty
/// (clean fast path) — see module rustdoc.
///
/// `target_repo` is currently unused by the v1 evaluator (CVE-only)
/// but is kept in the signature for forward compatibility with the
/// curation/age/signature gates that will fire on the target side.
/// The reference is taken to keep the call shape stable when those
/// land. `target_repo` would also be needed if a future enhancement
/// supports per-repo override of `require_approval` independent of
/// the active scan policy.
pub fn evaluate_promotion(
    artifact: &Artifact,
    target_repo: &Repository,
    policy: Option<&ScanPolicyProjection>,
    last_scan_summary: Option<&SeveritySummary>,
    exclusions: &[ExclusionProjection],
    now: DateTime<Utc>,
) -> PromotionOutcome {
    // `_target_repo` reserved for the per-target-repo gates that land
    // when curation / age / signature ports ship. The reference is
    // dropped so unused-variable-warnings stay quiet without an
    // attribute on the public function.
    let _ = target_repo;

    // Step 1 — coords for the exclusion filter's `package_pattern`
    // matcher. `coords.format` is reconstructed from the artifact + a
    // sentinel format because the pure-domain layer must not reach
    // across to the repository repository to resolve the real format
    // here. The exclusion filter only consults `coords.name` (see
    // `exclusion::filter_excluded_findings`), so the sentinel is
    // safe. The same approach is used by `re_evaluate_after_exclusion`.
    let coords = ArtifactCoords {
        name: artifact.name.clone(),
        name_as_published: artifact.name_as_published.clone(),
        version: artifact.version.clone(),
        path: artifact.path.clone(),
        format: crate::entities::repository::RepositoryFormat::Other(String::new()),
        metadata: serde_json::Value::Null,
    };

    // Step 2 — drop excluded findings. Missing scan summary becomes a
    // synthetic empty summary (the clean-baseline fast path).
    let owned_default;
    let summary: &SeveritySummary = match last_scan_summary {
        Some(s) => s,
        None => {
            owned_default = SeveritySummary {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 0,
            };
            &owned_default
        }
    };
    let filtered = filter_excluded_summary(summary, exclusions, &coords, now);

    // Step 3 — resolve threshold. Default-policy fallback when no
    // operator policy is active.
    let threshold = policy
        .map(|p| p.severity_threshold)
        .unwrap_or_else(DefaultPolicy::block_on_critical);

    // Step 4 — accumulate CVE-threshold violations with severity
    // escalation. v1 stops here; license / age ride along
    // when their ports ship (see module rustdoc TODO).
    let mut accumulator = ViolationsAccumulator::new();
    accumulator
        .collect_with_severity_escalation(evaluate_cve_thresholds(&filtered.remaining, threshold));

    // Step 5 — translate accumulator outcome into PromotionOutcome.
    let (action, violations) = accumulator.into_outcome();
    let require_approval = policy.map(|p| p.require_approval).unwrap_or(false);

    match action {
        PolicyAction::Block => PromotionOutcome::Reject(violations),
        PolicyAction::Warn => PromotionOutcome::Warn(violations),
        PolicyAction::Allow if require_approval => PromotionOutcome::RequireApproval(violations),
        PolicyAction::Allow => PromotionOutcome::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::artifact::QuarantineStatus;
    use crate::entities::managed_by::ManagedBy;
    use crate::entities::repository::{
        IndexMode, PrefetchPolicy, ReplicationPriority, RepositoryFormat, RepositoryType,
    };
    use crate::entities::scan_policy::{ProvenanceMode, SeverityThreshold};
    use crate::events::PolicyScope;
    use crate::types::ContentHash;
    use chrono::TimeZone;
    use uuid::Uuid;

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0)
            .single()
            .expect("fixed timestamp")
    }

    fn artifact(name: &str) -> Artifact {
        Artifact {
            id: Uuid::from_u128(1),
            repository_id: Uuid::from_u128(2),
            name: name.into(),
            name_as_published: name.into(),
            version: Some("1.0.0".into()),
            path: format!("{name}/1.0.0/{name}-1.0.0.tgz"),
            size_bytes: 1024,
            sha256_checksum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse::<ContentHash>()
                .expect("valid sha256"),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/gzip".into(),
            quarantine_status: QuarantineStatus::Released,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: ts(0),
            updated_at: ts(0),
        }
    }

    fn repository() -> Repository {
        Repository {
            id: Uuid::from_u128(3),
            key: "target".into(),
            name: "Target Repo".into(),
            description: None,
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Hosted,
            storage_backend: "filesystem".into(),
            storage_path: "/data/repos/target".into(),
            upstream_url: None,
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode: IndexMode::ReleasedOnly,
            prefetch_policy: PrefetchPolicy::default(),
            created_at: ts(0),
            updated_at: ts(0),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    fn projection(threshold: SeverityThreshold, require_approval: bool) -> ScanPolicyProjection {
        ScanPolicyProjection {
            policy_id: Uuid::from_u128(0xa11ce),
            name: "test-policy".into(),
            scope: PolicyScope::Global,
            severity_threshold: threshold,
            quarantine_duration_secs: 0,
            require_approval,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            stream_version: 0,
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

    fn empty_summary() -> SeveritySummary {
        summary(0, 0, 0, 0)
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
            cve_id: cve_id.into(),
            package_pattern: package_pattern.map(str::to_string),
            scope: PolicyScope::Global,
            reason: "test".into(),
            added_by_actor_id: None,
            expires_at,
        }
    }

    // ---- Allow path -------------------------------------------------------

    #[test]
    fn no_policy_no_findings_returns_allow() {
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            None,
            Some(&empty_summary()),
            &[],
            ts(0),
        );
        assert_eq!(r, PromotionOutcome::Allow);
    }

    #[test]
    fn no_policy_no_scan_summary_returns_allow() {
        // Missing scan summary is the clean-baseline fast path.
        let r = evaluate_promotion(&artifact("pkg"), &repository(), None, None, &[], ts(0));
        assert_eq!(r, PromotionOutcome::Allow);
    }

    #[test]
    fn policy_with_no_findings_no_approval_returns_allow() {
        let policy = projection(SeverityThreshold::Low, false);
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            Some(&policy),
            Some(&empty_summary()),
            &[],
            ts(0),
        );
        assert_eq!(r, PromotionOutcome::Allow);
    }

    #[test]
    fn policy_low_threshold_high_finding_under_default_no_approval_returns_allow() {
        // Default policy is Critical-only — high passes through clean.
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            None,
            Some(&summary(0, 5, 0, 0)),
            &[],
            ts(0),
        );
        assert_eq!(r, PromotionOutcome::Allow);
    }

    // ---- Reject path ------------------------------------------------------

    #[test]
    fn critical_finding_no_policy_rejects_via_default() {
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            None,
            Some(&summary(1, 0, 0, 0)),
            &[],
            ts(0),
        );
        match r {
            PromotionOutcome::Reject(violations) => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].severity, SeverityThreshold::Critical);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn critical_finding_low_threshold_policy_rejects() {
        let policy = projection(SeverityThreshold::Low, false);
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            Some(&policy),
            Some(&summary(1, 0, 0, 0)),
            &[],
            ts(0),
        );
        match r {
            PromotionOutcome::Reject(violations) => {
                assert_eq!(violations.len(), 1);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn high_finding_high_threshold_rejects_even_with_approval_required() {
        // require_approval = true does NOT downgrade Block to RequireApproval —
        // a hard reject stays a reject regardless of approval flag.
        let policy = projection(SeverityThreshold::High, true);
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            Some(&policy),
            Some(&summary(0, 1, 0, 0)),
            &[],
            ts(0),
        );
        match r {
            PromotionOutcome::Reject(violations) => assert_eq!(violations.len(), 1),
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // ---- Warn path --------------------------------------------------------

    #[test]
    fn medium_finding_low_threshold_warns() {
        // Low threshold → medium produces a violation; severity Medium
        // escalates to Warn (not Block).
        let policy = projection(SeverityThreshold::Low, false);
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            Some(&policy),
            Some(&summary(0, 0, 0, 1)),
            &[],
            ts(0),
        );
        match r {
            PromotionOutcome::Warn(violations) => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].severity, SeverityThreshold::Low);
            }
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    #[test]
    fn medium_finding_low_threshold_warns_even_with_approval_required() {
        // require_approval doesn't promote Warn to RequireApproval — Warn
        // is a non-blocking finding that proceeds with audit.
        let policy = projection(SeverityThreshold::Low, true);
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            Some(&policy),
            Some(&summary(0, 0, 1, 0)),
            &[],
            ts(0),
        );
        match r {
            PromotionOutcome::Warn(violations) => {
                assert_eq!(violations.len(), 1);
            }
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    // ---- RequireApproval path --------------------------------------------

    #[test]
    fn no_findings_policy_require_approval_true_returns_require_approval_with_empty() {
        let policy = projection(SeverityThreshold::Critical, true);
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            Some(&policy),
            Some(&empty_summary()),
            &[],
            ts(0),
        );
        match r {
            PromotionOutcome::RequireApproval(violations) => {
                assert!(violations.is_empty());
            }
            other => panic!("expected RequireApproval, got {other:?}"),
        }
    }

    #[test]
    fn missing_scan_summary_policy_require_approval_true_returns_require_approval() {
        // Clean-baseline fast path + require_approval = true.
        let policy = projection(SeverityThreshold::Critical, true);
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            Some(&policy),
            None,
            &[],
            ts(0),
        );
        assert_eq!(r, PromotionOutcome::RequireApproval(vec![]));
    }

    #[test]
    fn high_finding_high_threshold_no_approval_blocks_not_require_approval() {
        // High at threshold High is a Block — RequireApproval only fires
        // when the accumulator action stays at Allow.
        let policy = projection(SeverityThreshold::High, false);
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            Some(&policy),
            Some(&summary(0, 1, 0, 0)),
            &[],
            ts(0),
        );
        match r {
            PromotionOutcome::Reject(_) => {}
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // ---- Exclusion interactions ------------------------------------------

    #[test]
    fn critical_finding_with_matching_exclusion_clears_to_allow() {
        // Exclusion zeroes the only finding — promotion path returns
        // Allow (default policy, no approval).
        let exs = vec![exclusion(1, "CVE-A", None, None)];
        let r = evaluate_promotion(
            &artifact("xz-utils"),
            &repository(),
            None,
            Some(&summary(1, 0, 0, 0)),
            &exs,
            ts(1_000_000),
        );
        assert_eq!(r, PromotionOutcome::Allow);
    }

    #[test]
    fn critical_finding_with_matching_exclusion_and_approval_required_returns_require_approval() {
        let policy = projection(SeverityThreshold::Critical, true);
        let exs = vec![exclusion(1, "CVE-A", None, None)];
        let r = evaluate_promotion(
            &artifact("xz-utils"),
            &repository(),
            Some(&policy),
            Some(&summary(1, 0, 0, 0)),
            &exs,
            ts(1_000_000),
        );
        match r {
            PromotionOutcome::RequireApproval(violations) => {
                assert!(
                    violations.is_empty(),
                    "violations should be empty after exclusion clears the only finding"
                );
            }
            other => panic!("expected RequireApproval, got {other:?}"),
        }
    }

    #[test]
    fn critical_finding_with_expired_exclusion_still_rejects() {
        let now = ts(2_000_000);
        let exs = vec![exclusion(1, "CVE-A", None, Some(ts(1_000_000)))];
        let r = evaluate_promotion(
            &artifact("any"),
            &repository(),
            None,
            Some(&summary(1, 0, 0, 0)),
            &exs,
            now,
        );
        match r {
            PromotionOutcome::Reject(violations) => {
                assert_eq!(violations.len(), 1);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn pattern_scoped_exclusion_only_matches_named_package() {
        // Exclusion with package_pattern `xz-*` does NOT clear a finding
        // on a `pkg` artifact — the CVE still rejects.
        let exs = vec![exclusion(1, "CVE-A", Some("xz-*"), None)];
        let r = evaluate_promotion(
            &artifact("pkg"),
            &repository(),
            None,
            Some(&summary(1, 0, 0, 0)),
            &exs,
            ts(0),
        );
        match r {
            PromotionOutcome::Reject(_) => {}
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // ---- PromotionOutcome derives ----------------------------------------

    #[test]
    fn promotion_outcome_clone_eq() {
        let a = PromotionOutcome::Allow;
        let b = a.clone();
        assert_eq!(a, b);

        let viol = PolicyViolation {
            rule: "test".into(),
            severity: SeverityThreshold::Critical,
            message: "msg".into(),
            details: serde_json::Value::Null,
        };
        let r1 = PromotionOutcome::Reject(vec![viol.clone()]);
        let r2 = PromotionOutcome::Reject(vec![viol.clone()]);
        assert_eq!(r1, r2);

        assert_ne!(PromotionOutcome::Allow, PromotionOutcome::Warn(vec![]));
        assert_ne!(
            PromotionOutcome::Warn(vec![viol.clone()]),
            PromotionOutcome::RequireApproval(vec![viol]),
        );
    }

    #[test]
    fn promotion_outcome_debug_formats() {
        for variant in [
            PromotionOutcome::Allow,
            PromotionOutcome::Warn(vec![]),
            PromotionOutcome::RequireApproval(vec![]),
            PromotionOutcome::Reject(vec![]),
        ] {
            let s = format!("{variant:?}");
            assert!(!s.is_empty());
        }
    }
}
