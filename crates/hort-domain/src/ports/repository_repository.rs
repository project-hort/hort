use uuid::Uuid;

use crate::entities::repository::Repository;
use crate::error::DomainResult;
use crate::types::{Page, PageRequest};

use super::BoxFuture;

/// Outbound port for repository persistence.
pub trait RepositoryRepository: Send + Sync {
    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Repository>>;
    fn find_by_key(&self, key: &str) -> BoxFuture<'_, DomainResult<Repository>>;
    fn list(
        &self,
        page: PageRequest,
        search: Option<&str>,
    ) -> BoxFuture<'_, DomainResult<Page<Repository>>>;
    fn save(&self, repository: &Repository) -> BoxFuture<'_, DomainResult<()>>;
    fn delete(&self, id: Uuid) -> BoxFuture<'_, DomainResult<()>>;
    fn get_virtual_members(
        &self,
        virtual_repo_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<Repository>>>;
    fn add_virtual_member(
        &self,
        virtual_repo_id: Uuid,
        member_repo_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<()>>;
    fn remove_virtual_member(
        &self,
        virtual_repo_id: Uuid,
        member_repo_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<()>>;
    fn get_storage_usage(&self, repo_id: Uuid) -> BoxFuture<'_, DomainResult<u64>>;

    /// Managed-write path used exclusively by
    /// `ApplyConfigUseCase`. Sets `managed_by = 'gitops'` and the
    /// `managed_by_digest` in the same statement so a partial write
    /// can't leave a managed row without its digest. The `repository`
    /// argument's own `managed_by` field is ignored — the port writes
    /// `GitOps` unconditionally.
    fn save_managed(
        &self,
        repository: &Repository,
        digest: &[u8; 32],
    ) -> BoxFuture<'_, DomainResult<()>>;

    /// Managed-write delete. Refuses to delete
    /// rows whose `managed_by != 'gitops'` (defence in depth — the
    /// diff layer never schedules such a delete, but the port enforces
    /// the invariant in case of out-of-band SQL or future bugs).
    fn delete_managed(&self, id: Uuid) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `RepositoryRepository` is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: size_of call executes in the test body for coverage.
        let _ = size_of::<&dyn RepositoryRepository>();
    }
}
