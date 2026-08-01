//! Shared active-scan-policy resolver (issue #76, item 1/2).
//!
//! Extracted from seven private, byte-identical copies of
//! `resolve_active_policy_for_repo` (in `quarantine_use_case.rs` — the
//! canonical copy, plus `discovery_use_case.rs`, `ingest_use_case.rs`,
//! `promotion_use_case.rs`, `scan_orchestration.rs`,
//! `provenance_orchestration.rs`, `seed_import_use_case.rs`). Pure
//! refactor: zero behavior change at any caller.

use uuid::Uuid;

use hort_domain::entities::scan_policy::ScanPolicyProjection;
use hort_domain::events::PolicyScope;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;

use crate::error::AppResult;

/// Resolve the active scan policy for `repo_id`.
///
/// Repo-scoped wins over global; absent both, the caller passes `None`
/// to the evaluator and `DefaultPolicy::block_on_critical` (or the
/// caller's own default) supplies the threshold. v1 simplification:
/// scans the projection list once per call. If projection counts grow
/// past low-thousands a dedicated `find_for_repo` port method becomes
/// the next step; today it is overhead the contention path doesn't
/// notice.
pub(crate) async fn resolve_active_policy_for_repo(
    policy_projections: &dyn PolicyProjectionRepository,
    repo_id: Uuid,
) -> AppResult<Option<ScanPolicyProjection>> {
    let active = policy_projections.list_active().await?;
    let mut repo_scoped: Option<ScanPolicyProjection> = None;
    let mut global: Option<ScanPolicyProjection> = None;
    for projection in active {
        match &projection.scope {
            PolicyScope::Repository(id) if *id == repo_id => {
                repo_scoped = Some(projection);
            }
            PolicyScope::Global if global.is_none() => {
                global = Some(projection);
            }
            _ => {}
        }
    }
    Ok(repo_scoped.or(global))
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use uuid::Uuid;

    use hort_domain::entities::scan_policy::{
        NegligibleAction, ProvenanceMode, ScanPolicyProjection, SeverityThreshold,
    };
    use hort_domain::events::PolicyScope;

    use crate::use_cases::test_support::MockPolicyProjectionRepository;

    fn projection(scope: PolicyScope) -> ScanPolicyProjection {
        ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: format!("test-policy-{}", Uuid::new_v4()),
            scope,
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs: 3600,
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
            stream_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn repo_scoped_wins_over_global() {
        let repo_id = Uuid::new_v4();
        let repo_policy = projection(PolicyScope::Repository(repo_id));
        let global_policy = projection(PolicyScope::Global);
        let repo = MockPolicyProjectionRepository::new();
        repo.insert(global_policy);
        repo.insert(repo_policy.clone());

        let resolved = resolve_active_policy_for_repo(&repo, repo_id)
            .await
            .unwrap();
        assert_eq!(resolved.map(|p| p.policy_id), Some(repo_policy.policy_id));
    }

    #[tokio::test]
    async fn global_fallback_when_no_repo_scoped_match() {
        let repo_id = Uuid::new_v4();
        let other_repo_id = Uuid::new_v4();
        let other_repo_policy = projection(PolicyScope::Repository(other_repo_id));
        let global_policy = projection(PolicyScope::Global);
        let repo = MockPolicyProjectionRepository::new();
        repo.insert(other_repo_policy);
        repo.insert(global_policy.clone());

        let resolved = resolve_active_policy_for_repo(&repo, repo_id)
            .await
            .unwrap();
        assert_eq!(resolved.map(|p| p.policy_id), Some(global_policy.policy_id));
    }

    #[tokio::test]
    async fn none_when_neither_scope_matches() {
        let repo_id = Uuid::new_v4();
        let other_repo_id = Uuid::new_v4();
        let other_repo_policy = projection(PolicyScope::Repository(other_repo_id));
        let repo = MockPolicyProjectionRepository::new();
        repo.insert(other_repo_policy);

        let resolved = resolve_active_policy_for_repo(&repo, repo_id)
            .await
            .unwrap();
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn none_when_no_active_policies_at_all() {
        let repo_id = Uuid::new_v4();
        let repo = MockPolicyProjectionRepository::new();

        let resolved = resolve_active_policy_for_repo(&repo, repo_id)
            .await
            .unwrap();
        assert!(resolved.is_none());
    }

    /// Multiple `Global` projections — exercises the `if
    /// global.is_none()` guard's "already set, skip" branch. Iteration
    /// order over the mock's map-backed store is not guaranteed, so
    /// this asserts a single, consistent pick from the candidate set
    /// rather than which one specifically.
    #[tokio::test]
    async fn exactly_one_global_selected_when_multiple_present() {
        let repo_id = Uuid::new_v4();
        let first_global = projection(PolicyScope::Global);
        let second_global = projection(PolicyScope::Global);
        let candidate_ids = [first_global.policy_id, second_global.policy_id];
        let repo = MockPolicyProjectionRepository::new();
        repo.insert(first_global);
        repo.insert(second_global);

        let resolved = resolve_active_policy_for_repo(&repo, repo_id)
            .await
            .unwrap()
            .expect("one global candidate must be selected");
        assert!(candidate_ids.contains(&resolved.policy_id));
    }

    /// Archived projections are excluded by the port's `list_active`
    /// contract before this helper ever sees them.
    #[tokio::test]
    async fn archived_global_projections_are_excluded() {
        let repo_id = Uuid::new_v4();
        let mut archived_global = projection(PolicyScope::Global);
        archived_global.archived = true;
        let active_global = projection(PolicyScope::Global);
        let repo = MockPolicyProjectionRepository::new();
        repo.insert(archived_global);
        repo.insert(active_global.clone());

        let resolved = resolve_active_policy_for_repo(&repo, repo_id)
            .await
            .unwrap();
        assert_eq!(resolved.map(|p| p.policy_id), Some(active_global.policy_id));
    }

    #[tokio::test]
    async fn propagates_infrastructure_error() {
        let repo_id = Uuid::new_v4();
        let repo = MockPolicyProjectionRepository::new();
        repo.fail_next_list_active(hort_domain::error::DomainError::Invariant(
            "projection store down".into(),
        ));

        let err = resolve_active_policy_for_repo(&repo, repo_id)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::AppError::Domain(hort_domain::error::DomainError::Invariant(_))
        ));
    }
}
