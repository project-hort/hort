//! Outbound port for `ServiceAccount` persistence.
//!
//! `ServiceAccount` is CRUD (not event-sourced) — the apply use case
//! (`ApplyConfigUseCase::apply_service_accounts`) is the only writer.
//!
//! The aggregate spans three rows: `service_accounts`,
//! `service_account_federated_identities`, and
//! `service_account_fallback_rotations`. The port returns the composed
//! aggregate — adapter impls compose the sub-aggregates inside their
//! read methods, and the `upsert` method takes the whole aggregate and
//! atomically replaces the federated-identity rows + upserts the
//! fallback rotation row in a single transaction.
//!
//! No `managed_by` field on the row: the
//! aggregate is exclusively gitops-managed.

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

    /// INSERT-or-UPDATE the SA aggregate atomically.
    ///
    /// The adapter runs the following inside a single transaction:
    /// 1. UPSERT on `service_accounts` keyed by `name`. The
    ///    caller-supplied `id` is the authoritative id for fresh
    ///    inserts; on update the existing row's id is preserved (`ON
    ///    CONFLICT (name) DO UPDATE`).
    /// 2. DELETE every existing `service_account_federated_identities`
    ///    row for the SA, then INSERT the new set preserving the order
    ///    from `aggregate.federated_identities` as the row `position`.
    /// 3. UPSERT (or DELETE if absent) the matching
    ///    `service_account_fallback_rotations` row.
    ///
    /// The replace-on-update pattern on the federated-identity rows is
    /// the simplest atomic shape — diff-aware "ALTER three rows" would
    /// duplicate the apply use case's intent. The transaction boundary
    /// is the safety net: a partial failure leaves the prior aggregate
    /// intact.
    fn upsert(&self, sa: &ServiceAccount) -> BoxFuture<'_, DomainResult<()>>;

    /// DELETE the SA row by `name`. The CASCADE FKs on
    /// `service_account_federated_identities.service_account_id` and
    /// `service_account_fallback_rotations.service_account_id` drop
    /// the sub-aggregate rows alongside.
    ///
    /// The backing `users` row is NOT deleted by this method — the
    /// apply pipeline manages the backing-user lifecycle directly
    /// (the backing user is shared infrastructure and may
    /// have other tokens scoped to it).
    fn delete_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<()>>;
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
