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
    /// **Atomically** replace a virtual repo's entire member set with
    /// `ordered_member_ids`, assigning `priority` = list index (0 = highest).
    ///
    /// Used by `ApplyConfigUseCase` to reconcile a changed member list. The
    /// clear-then-re-add MUST be one transaction: a concurrent reader (another
    /// replica serving against the shared DB during a rolling deploy) must see
    /// either the old set or the new set, **never a partial set**. A partial
    /// set with the owner edge transiently removed would make an owned name
    /// look unowned, momentarily un-suppressing proxies and re-opening the
    /// dependency-confusion window (ADR 0031 rule 2b). Replacing the prior
    /// non-transactional remove-loop-then-add-loop closes that window.
    fn replace_virtual_members(
        &self,
        virtual_repo_id: Uuid,
        ordered_member_ids: &[Uuid],
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
