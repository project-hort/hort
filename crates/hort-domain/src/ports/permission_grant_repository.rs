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
//! The trait surface is deliberately minimal: the composition root reads the
//! full grant set once at startup (`list_all`) to build the
//! `RbacEvaluator`; the gitops apply pipeline reconciles the entire
//! `managed_by = gitops` partition via `save_managed` (the
//! authoritative-set reconcile primitive) and inspects the managed
//! subset for the apply diff via `list_managed_by_gitops`. There is no
//! live-refresh path — restart-to-apply remains the contract, the
//! same read-once-at-boot shape the dropped `RoleRepository` had.
//!
//! **`save_managed` is the reconcile/revoke primitive**:
//! there is no separate `delete_*` method. An earlier per-row signature
//! diverged from the revoke + minimal-port design intent; the
//! plan-aligned shape is "here is the complete gitops-managed set,
//! reconcile to it atomically."

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

    /// Reconcile the **entire** `managed_by = 'gitops'` partition to
    /// `items` — the authoritative complete gitops-managed grant set
    /// In a single transaction the
    /// adapter:
    ///
    /// - deletes every `managed_by = 'gitops'` row whose subject-
    ///   dependent identity (`(sorted required_claims, repository_id,
    ///   permission)` for `Claims`; `(user_id, repository_id,
    ///   permission)` for `User`) is absent from
    ///   `items` (delete-absent), then
    /// - upserts every row in `items` keyed on that same identity, not
    ///   the surrogate primary key, so replaying an unchanged gitops
    ///   set is a no-op (upsert-present).
    ///
    /// `save_managed` IS the reconcile/revoke primitive — there is no
    /// separate `delete_*` method. An empty `items` slice therefore
    /// revokes every gitops-managed grant (an explicitly-emptied
    /// config). Every element must carry `managed_by_digest`; the
    /// adapter writes `managed_by = 'gitops'` unconditionally.
    /// Revoke/apply audit events are emitted by the use case,
    /// NOT here.
    fn save_managed(&self, items: &[PermissionGrant]) -> BoxFuture<'_, DomainResult<()>>;
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
