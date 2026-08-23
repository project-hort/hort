//! `EffectiveRepositoryConfigUseCase`.
//!
//! Admin-only read of the scan-policy leg of a repository's *effective*
//! config — the resolved-policy half behind
//! `GET /api/v1/admin/repositories/:key/effective-config`. The repository
//! row and its upstream mappings are already reachable through
//! `RepositoryUseCase::get_by_key` and the `repository_upstream_mappings`
//! port; the scan/retention policy binding is not, because
//! `PolicyProjectionRepository` and the shared
//! [`resolve_active_policy_for_repo`] resolver are both `pub(crate)` inside
//! this crate (ADR 0008) — no inbound HTTP handler may touch either
//! directly. This use case is the thin read that closes that gap.
//!
//! No new SQL: [`Self::effective_scan_policy`] reuses the exact resolution
//! [`QuarantineUseCase::is_window_elapsed`](crate::use_cases::quarantine_use_case::QuarantineUseCase)
//! and [`QuarantineUseCase::resolve_release_authority`] already perform
//! (repo-scoped policy wins over global; absent both, the built-in
//! [`DefaultPolicy`] supplies every field) — so this admin-facing read can
//! never disagree with what the release path actually enforces.

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::scan_policy::{NegligibleAction, ScanEnforcement, SeverityThreshold};
use hort_domain::events::ApiActor;
use hort_domain::policy::scan::DefaultPolicy;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;

use crate::error::AppResult;
use crate::use_cases::policy_resolution::resolve_active_policy_for_repo;
use crate::use_cases::CallerPrivileges;

/// Effective (resolved) scan-policy view for a repository.
///
/// `policy_id` / `policy_name` are `None` when no policy — repo-scoped or
/// global — is bound; every other field still carries a value, resolved
/// from [`DefaultPolicy`] in that case. Read-only projection: never itself
/// a release authority (ADR 0007 — that decision stays with
/// `QuarantineUseCase`).
#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveScanPolicyView {
    pub policy_id: Option<Uuid>,
    pub policy_name: Option<String>,
    pub severity_threshold: SeverityThreshold,
    pub scan_backends: Vec<String>,
    pub enforcement: ScanEnforcement,
    pub negligible_action: NegligibleAction,
    pub quarantine_duration_secs: i64,
}

/// Application use case backing the policy leg of
/// `GET /api/v1/admin/repositories/:key/effective-config`.
pub struct EffectiveRepositoryConfigUseCase {
    policy_projections: Arc<dyn PolicyProjectionRepository>,
}

impl EffectiveRepositoryConfigUseCase {
    pub fn new(policy_projections: Arc<dyn PolicyProjectionRepository>) -> Self {
        Self { policy_projections }
    }

    /// Resolve the effective scan policy bound to `repository_id`
    /// (repo-scoped > global > [`DefaultPolicy`]).
    ///
    /// Admin-only — non-admin callers are denied before the projection
    /// repository is read (defence-in-depth; the HTTP edge already gates
    /// via the `AdminPrincipal` extractor).
    #[tracing::instrument(skip(self, privileges))]
    pub async fn effective_scan_policy(
        &self,
        actor: ApiActor,
        privileges: CallerPrivileges,
        repository_id: Uuid,
    ) -> AppResult<EffectiveScanPolicyView> {
        if let Err(e) = privileges.require_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                %repository_id,
                "effective-scan-policy read denied: not admin",
            );
            return Err(e);
        }

        let policy =
            resolve_active_policy_for_repo(&*self.policy_projections, repository_id).await?;

        let view = match policy {
            Some(p) => EffectiveScanPolicyView {
                policy_id: Some(p.policy_id),
                policy_name: Some(p.name),
                severity_threshold: p.severity_threshold,
                scan_backends: p.scan_backends,
                enforcement: p.enforcement,
                negligible_action: p.negligible_action,
                quarantine_duration_secs: p.quarantine_duration_secs,
            },
            None => EffectiveScanPolicyView {
                policy_id: None,
                policy_name: None,
                severity_threshold: DefaultPolicy::block_on_critical(),
                scan_backends: DefaultPolicy::block_on_critical_default_backends(),
                enforcement: DefaultPolicy::enforcement(),
                negligible_action: DefaultPolicy::negligible_action(),
                quarantine_duration_secs: DefaultPolicy::quarantine_duration_secs(),
            },
        };

        tracing::debug!(repository_id = %repository_id, "admin read effective scan policy");
        Ok(view)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use hort_domain::entities::scan_policy::{
        ProvenanceMode, ScanPolicyProjection, SeverityThreshold,
    };
    use hort_domain::error::DomainError;
    use hort_domain::events::PolicyScope;

    use super::*;
    use crate::use_cases::test_support::{
        admin_privileges, api_actor, reviewer_privileges, unprivileged,
        MockPolicyProjectionRepository,
    };

    fn projection(scope: PolicyScope) -> ScanPolicyProjection {
        ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: "repo-scan-policy".into(),
            scope,
            severity_threshold: SeverityThreshold::High,
            quarantine_duration_secs: 7200,
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string(), "osv".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Warn,
            enforcement: ScanEnforcement::Record,
            stream_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn effective_scan_policy_admin_no_policy_returns_default_policy_view() {
        let repo_id = Uuid::new_v4();
        let projections = Arc::new(MockPolicyProjectionRepository::new());
        let uc = EffectiveRepositoryConfigUseCase::new(projections);

        let view = uc
            .effective_scan_policy(api_actor(), admin_privileges(), repo_id)
            .await
            .expect("admin happy path");

        assert_eq!(view.policy_id, None);
        assert_eq!(view.policy_name, None);
        assert_eq!(view.severity_threshold, DefaultPolicy::block_on_critical());
        assert_eq!(
            view.scan_backends,
            DefaultPolicy::block_on_critical_default_backends()
        );
        assert_eq!(view.enforcement, DefaultPolicy::enforcement());
        assert_eq!(view.negligible_action, DefaultPolicy::negligible_action());
        assert_eq!(
            view.quarantine_duration_secs,
            DefaultPolicy::quarantine_duration_secs()
        );
    }

    #[tokio::test]
    async fn effective_scan_policy_admin_repo_scoped_wins_over_global() {
        let repo_id = Uuid::new_v4();
        let repo_policy = projection(PolicyScope::Repository(repo_id));
        let global_policy = projection(PolicyScope::Global);
        let projections = Arc::new(MockPolicyProjectionRepository::new());
        projections.insert(global_policy);
        projections.insert(repo_policy.clone());
        let uc = EffectiveRepositoryConfigUseCase::new(projections);

        let view = uc
            .effective_scan_policy(api_actor(), admin_privileges(), repo_id)
            .await
            .expect("admin happy path");

        assert_eq!(view.policy_id, Some(repo_policy.policy_id));
        assert_eq!(view.policy_name, Some(repo_policy.name));
        assert_eq!(view.severity_threshold, SeverityThreshold::High);
        assert_eq!(
            view.scan_backends,
            vec!["trivy".to_string(), "osv".to_string()]
        );
        assert_eq!(view.enforcement, ScanEnforcement::Record);
        assert_eq!(view.negligible_action, NegligibleAction::Warn);
        assert_eq!(view.quarantine_duration_secs, 7200);
    }

    #[tokio::test]
    async fn effective_scan_policy_admin_falls_back_to_global_when_no_repo_scoped_policy() {
        let repo_id = Uuid::new_v4();
        let global_policy = projection(PolicyScope::Global);
        let projections = Arc::new(MockPolicyProjectionRepository::new());
        projections.insert(global_policy.clone());
        let uc = EffectiveRepositoryConfigUseCase::new(projections);

        let view = uc
            .effective_scan_policy(api_actor(), admin_privileges(), repo_id)
            .await
            .expect("admin happy path");

        assert_eq!(view.policy_id, Some(global_policy.policy_id));
        assert_eq!(view.policy_name, Some(global_policy.name));
    }

    #[tokio::test]
    async fn effective_scan_policy_reviewer_returns_forbidden_and_does_not_read_projections() {
        let repo_id = Uuid::new_v4();
        let projections = Arc::new(MockPolicyProjectionRepository::new());
        projections.insert(projection(PolicyScope::Global));
        let uc = EffectiveRepositoryConfigUseCase::new(projections);

        let err = uc
            .effective_scan_policy(api_actor(), reviewer_privileges(), repo_id)
            .await
            .expect_err("reviewer must be forbidden");
        assert!(matches!(
            err,
            crate::error::AppError::Domain(DomainError::Forbidden(_))
        ));
    }

    /// Fully unprivileged caller — pins the `is_reviewer = false` arm of
    /// `require_admin()` for branch coverage.
    #[tokio::test]
    async fn effective_scan_policy_unprivileged_returns_forbidden() {
        let repo_id = Uuid::new_v4();
        let projections = Arc::new(MockPolicyProjectionRepository::new());
        let uc = EffectiveRepositoryConfigUseCase::new(projections);

        let err = uc
            .effective_scan_policy(api_actor(), unprivileged(), repo_id)
            .await
            .expect_err("unprivileged must be forbidden");
        assert!(matches!(
            err,
            crate::error::AppError::Domain(DomainError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn effective_scan_policy_propagates_projection_repository_error() {
        let repo_id = Uuid::new_v4();
        let projections = Arc::new(MockPolicyProjectionRepository::new());
        projections.fail_next_list_active(DomainError::Invariant("projections unavailable".into()));
        let uc = EffectiveRepositoryConfigUseCase::new(projections);

        let err = uc
            .effective_scan_policy(api_actor(), admin_privileges(), repo_id)
            .await
            .expect_err("projection repository error must propagate");
        assert!(matches!(
            err,
            crate::error::AppError::Domain(DomainError::Invariant(_))
        ));
    }
}
