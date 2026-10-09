//! Outbound port for `ServiceAccount` persistence.
//!
//! `ServiceAccount` is CRUD (not event-sourced) — the apply use case
//! (`ApplyConfigUseCase::apply_service_accounts`) is the only writer.
//!
//! The aggregate spans three rows: `service_accounts`,
//! `service_account_federated_identities`, and
//! `service_account_fallback_rotations`. The port returns the composed
//! aggregate — adapter impls compose the sub-aggregates inside their
//! read methods.
//!
//! No `managed_by` field on the row: the
//! aggregate is exclusively gitops-managed.
//!
//! **This port is read-only.** The write is
//! [`AuthorityLifecyclePort::commit_service_accounts`], which takes the
//! whole aggregate, atomically replaces the federated-identity rows +
//! upserts the fallback-rotation row, **and** appends the attesting
//! `ServiceAccountCreated` / `ServiceAccountUpdated` /
//! `ServiceAccountDeleted` event — all in one transaction. A service
//! account is a federated-identity trust anchor: its
//! `federated_identities[].claims` decide which JWTs may assume it, and
//! the federation handler reads the aggregate at assume time. See
//! [`crate::ports::permission_grant_repository`] for why the write
//! methods are *removed* from this trait rather than left unused.
//!
//! [`AuthorityLifecyclePort::commit_service_accounts`]:
//!     crate::ports::authority_lifecycle::AuthorityLifecyclePort::commit_service_accounts

use crate::entities::service_account::ServiceAccount;
use crate::error::DomainResult;

use super::BoxFuture;

/// Persistence port for the `service_accounts` aggregate.
///
/// Implementations live in `hort-adapters-postgres::service_account_repo`.
pub trait ServiceAccountRepository: Send + Sync {
    /// Every declared service account, with sub-aggregates
    /// (`federated_identities`, `fallback_rotation`) composed.
    ///
    /// The apply pipeline reads this to build the current-snapshot view
    /// for the diff; bounded by the operator's CRD count (typically
    /// <100). The composition happens inside the adapter — one query
    /// per side, joined in Rust to avoid an N+1.
    fn list(&self) -> BoxFuture<'_, DomainResult<Vec<ServiceAccount>>>;

    /// Lookup by the CRD `metadata.name` with sub-aggregates composed.
    /// Returns `None` when no SA with that name exists.
    fn get_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<Option<ServiceAccount>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `ServiceAccountRepository` is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn ServiceAccountRepository>();
    }
}
