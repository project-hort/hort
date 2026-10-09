//! Outbound port for the `claim_mappings` table (ADR 0012;
//! replaces the dropped `GroupMappingRepository`).
//!
//! Claim mappings translate an IdP `groups`-claim string into a registry
//! claim name. The boot caller reads `list_all` to build the
//! `Vec<ClaimMapping>` that `AuthenticateUseCase` consumes
//! (`resolve_claims` flattens the caller's `groups` claim against
//! it). The gitops apply pipeline inspects the managed subset for its
//! diff via `list_managed_by_gitops`.
//!
//! Restart-to-apply remains the contract — there is no live-refresh
//! path, the same shape the dropped `GroupMappingRepository` had.
//!
//! **This port is read-only.** The write — the authoritative-set
//! reconcile of the whole `managed_by = 'gitops'` partition — is
//! [`AuthorityLifecyclePort::commit_claim_mappings`], which commits the
//! reconcile **and** the `ClaimMappingApplied` / `ClaimMappingRevoked`
//! events that attest it in one transaction. See
//! [`crate::ports::permission_grant_repository`] for why the write
//! method is *removed* from this trait rather than left unused.
//!
//! [`AuthorityLifecyclePort::commit_claim_mappings`]:
//!     crate::ports::authority_lifecycle::AuthorityLifecyclePort::commit_claim_mappings

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
