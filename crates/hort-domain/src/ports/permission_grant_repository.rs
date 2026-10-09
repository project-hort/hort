//! Outbound port for the `permission_grants` table (ADR 0012).
//!
//! Permission-grant persistence is split out of the dropped
//! `RoleRepository`: there is no `roles` table and no `role_id` to key
//! grants on. A grant now carries a sum-typed
//! [`GrantSubject`](crate::entities::rbac::GrantSubject) —
//! `Claims(required_claims[])` XOR `User(user_id)` — mapped from the two
//! mutually-exclusive columns (`subject_exclusive` CHECK enforces the XOR
//! at the DB layer).
//!
//! **This port is read-only.** The composition root reads the full
//! grant set once at startup (`list_all`) to build the
//! `RbacEvaluator`, and the gitops apply pipeline inspects the managed
//! subset for its diff via `list_managed_by_gitops`. There is no
//! live-refresh path — restart-to-apply remains the contract, the same
//! read-once-at-boot shape the dropped `RoleRepository` had.
//!
//! The write — the authoritative-set reconcile of the whole
//! `managed_by = 'gitops'` partition — is
//! [`AuthorityLifecyclePort::commit_permission_grants`], which commits
//! the reconcile **and** the `PermissionGrantApplied` /
//! `PermissionGrantRevoked` events that attest it in one transaction.
//! It used to live here as `save_managed`, committing on its own, and
//! the use case appended afterwards: an append failure left the grant
//! live with nothing in the authorization stream attesting it, in a
//! state no retry could repair (the next apply diffs against the
//! already-changed rows and emits nothing). The method is gone from
//! this trait rather than merely unused, so a future apply branch
//! cannot reintroduce the dual write — the mistake is a compile error.
//!
//! [`AuthorityLifecyclePort::commit_permission_grants`]:
//!     crate::ports::authority_lifecycle::AuthorityLifecyclePort::commit_permission_grants

use crate::entities::rbac::PermissionGrant;
use crate::error::DomainResult;

use super::BoxFuture;

/// Outbound port for the `permission_grants` table.
pub trait PermissionGrantRepository: Send + Sync {
    /// Full snapshot of every grant (managed_by ∈ {local, gitops}). Used
    /// by the composition root to build the
    /// [`RbacEvaluator`](../../hort_app/rbac/struct.RbacEvaluator.html) at
    /// startup. The mapper translates `(required_claims, user_id)` into
    /// the [`GrantSubject`](crate::entities::rbac::GrantSubject) sum type.
    fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>>;

    /// Every gitops-managed grant. Bounded by the partial index
    /// `idx_permission_grants_managed_by` (`001_users_roles_rbac.sql`) —
    /// this is the diff query the gitops apply pipeline runs on every
    /// boot. The diff identity is subject-dependent:
    /// `(sorted required_claims, repository_id, permission)` for `Claims`,
    /// `(user_id, repository_id, permission)` for `User`.
    fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `PermissionGrantRepository` is
    /// dyn-compatible — the composition root holds it behind an
    /// `Arc<dyn PermissionGrantRepository>`.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn PermissionGrantRepository>();
    }
}
