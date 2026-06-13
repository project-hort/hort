//! Outbound port for the `claim_mappings` table (ADR 0012;
//! replaces the dropped `GroupMappingRepository`).
//!
//! Claim mappings translate an IdP `groups`-claim string into a registry
//! claim name. The boot caller reads `list_all` to build the
//! `Vec<ClaimMapping>` that `AuthenticateUseCase` consumes
//! (`resolve_claims` flattens the caller's `groups` claim against
//! it). The gitops apply pipeline writes managed rows via `save_managed`
//! and inspects the managed subset for the apply diff via
//! `list_managed_by_gitops`.
//!
//! Restart-to-apply remains the contract — there is no live-refresh
//! path, the same shape the dropped `GroupMappingRepository` had. The
//! trait surface is deliberately minimal: list, save_managed (the
//! authoritative-set reconcile primitive — there is no separate
//! `delete_*`), list_managed_by_gitops.

use crate::entities::rbac::ClaimMapping;
use crate::error::DomainResult;

use super::BoxFuture;

/// Outbound port for the `claim_mappings` table.
pub trait ClaimMappingRepository: Send + Sync {
    /// Every mapping (managed_by ∈ {local, gitops}). The boot caller
    /// consumes this once to build the `AuthenticateUseCase` — there is
    /// no per-mapping `managed_by` signal at authentication time.
    fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<ClaimMapping>>>;

    /// Every gitops-managed mapping. Bounded by the partial index path
    /// on `managed_by` — this is the diff query the gitops apply
    /// pipeline runs on every boot.
    fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<ClaimMapping>>>;

    /// Reconcile the **entire** `managed_by = 'gitops'` partition to
    /// `items` — the authoritative complete gitops-managed mapping set.
    /// In a single transaction the
    /// adapter deletes every `managed_by = 'gitops'` row whose
    /// `(idp_group, claim)` identity (the table's UNIQUE key) is absent
    /// from `items` (delete-absent), then upserts every row in `items`
    /// on that same key (upsert-present) so replaying an unchanged
    /// gitops set is a no-op.
    ///
    /// `save_managed` IS the reconcile/revoke primitive — there is no
    /// separate `delete_*` method. An empty `items` slice revokes every
    /// gitops-managed mapping. Every element must carry
    /// `managed_by_digest`; the adapter writes `managed_by = 'gitops'`
    /// unconditionally. Revoke/apply audit events are emitted by the
    /// use case, NOT here.
    fn save_managed(&self, items: &[ClaimMapping]) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `ClaimMappingRepository` is
    /// dyn-compatible — the composition root holds it behind an
    /// `Arc<dyn ClaimMappingRepository>`.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn ClaimMappingRepository>();
    }
}
