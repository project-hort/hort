//! PostgreSQL write-side adapter for the authority rows plus their
//! audit events.
//!
//! Implements [`AuthorityLifecyclePort`]. Each method wraps the row
//! write(s) and every audit batch in a single transaction via
//! [`PgEventStore::append_in_tx`], so neither side can land without the
//! other. Same construction as [`crate::ref_lifecycle::PgRefLifecycle`]
//! — the transaction handle comes from
//! `event_store.begin_unit_of_work()`, so no separate pool handle is
//! needed, and the row SQL is the module-local `*_in_tx` helper the
//! corresponding repository adapter already uses for its own
//! single-purpose transaction (one definition of each statement group,
//! two transaction boundaries).
//!
//! # Statement order: rows first, then the appends
//!
//! Mirrors `PgRefLifecycle`, which writes the projection row and then
//! calls `append_in_tx`. Two reasons it is the right order here:
//!
//! - It is what makes the rollback *observable and testable*. The
//!   failure this adapter exists to prevent is an append that fails
//!   after the row is already durable; with the rows written first, a
//!   failing append has real uncommitted row changes to roll back, and
//!   `tests/authority_audit_atomicity.rs` asserts exactly that. Append
//!   first would make the same test pass because the row write never
//!   ran — a weaker proof of the same promise.
//! - It cannot form a lock cycle with the `events`-first lifecycle
//!   adapters. A cycle needs two transactions taking the same two
//!   tables in opposite order; `PgArtifactLifecycle` (events →
//!   artifacts → …) never touches `permission_grants`,
//!   `claim_mappings`, `oidc_issuers`,
//!   `repository_upstream_mappings` or the `service_accounts`
//!   aggregate, and gitops apply is single-flight per boot lock, so
//!   two authority transactions do not overlap either.
//!
//! # The multi-stream append is one unit
//!
//! A permission-grant reconcile routes its events per row to the
//! repository stream (repo-scoped grant) or the global authorization
//! stream (wildcard grant), so one reconcile can produce several
//! batches; an upstream-mapping apply is repo-scoped on every row, so
//! it produces one batch per repository it touches. They are appended
//! with several `append_in_tx` calls on the
//! **same** `PgUnitOfWork`, which is what makes the whole list atomic:
//! a batch that fails part-way through the list leaves no stream
//! audited and no row written. The pre-port shape — one
//! `EventStore::append` per stream, each its own transaction — could
//! leave some repository streams audited and others not.

use std::sync::Arc;

use hort_domain::entities::rbac::{ClaimMapping, PermissionGrant};
use hort_domain::error::DomainResult;
use hort_domain::ports::authority_lifecycle::{
    AuthorityLifecyclePort, OidcIssuerChange, ServiceAccountCommit, UpstreamMappingCommit,
};
use hort_domain::ports::event_store::AppendEvents;
use hort_domain::ports::BoxFuture;

use crate::claim_mapping_repo::{
    prepare_managed_claim_mappings, reconcile_managed_claim_mappings_in_tx,
};
use crate::event_store::{PgEventStore, PgUnitOfWork};
use crate::oidc_issuer_repo::{delete_by_name_in_tx, upsert_in_tx};
use crate::permission_grant_repo::{prepare_managed_grants, reconcile_managed_grants_in_tx};
use crate::repository_upstream_mapping_repo::{delete_managed_by_id_in_tx, save_managed_in_tx};
use crate::service_account_repo::{
    delete_by_name_in_tx as delete_service_account_by_name_in_tx,
    upsert_in_tx as upsert_service_account_in_tx,
};

/// PostgreSQL implementation of [`AuthorityLifecyclePort`].
pub struct PgAuthorityLifecycle {
    event_store: Arc<PgEventStore>,
}

impl PgAuthorityLifecycle {
    /// Construct the adapter. The transactional path goes through
    /// `event_store.begin_unit_of_work()`; no separate pool handle is
    /// needed.
    pub fn new(event_store: Arc<PgEventStore>) -> Self {
        Self { event_store }
    }

    /// Append every caller-built batch inside the open unit of work.
    ///
    /// The batches are appended verbatim — this adapter never inspects
    /// or re-serialises a `DomainEvent` payload (the port's
    /// pass-through rule). An empty list is a legitimate no-op: an
    /// unchanged gitops replay reconciles its partition and emits
    /// nothing.
    async fn append_all(
        &self,
        uow: &mut PgUnitOfWork,
        batches: Vec<AppendEvents>,
    ) -> DomainResult<()> {
        for batch in batches {
            self.event_store.append_in_tx(uow, batch).await?;
        }
        Ok(())
    }
}

impl AuthorityLifecyclePort for PgAuthorityLifecycle {
    fn commit_permission_grants<'a>(
        &'a self,
        desired: &'a [PermissionGrant],
        batches: Vec<AppendEvents>,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            // Reject a digest-less managed grant before a transaction
            // is opened — same precondition the repository's own
            // reconcile enforces.
            let prepared = prepare_managed_grants(desired)?;
            let mut uow = self.event_store.begin_unit_of_work().await?;
            reconcile_managed_grants_in_tx(uow.conn(), &prepared).await?;
            self.append_all(&mut uow, batches).await?;
            uow.commit().await
        })
    }

    fn commit_claim_mappings<'a>(
        &'a self,
        desired: &'a [ClaimMapping],
        batches: Vec<AppendEvents>,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            let prepared = prepare_managed_claim_mappings(desired)?;
            let mut uow = self.event_store.begin_unit_of_work().await?;
            reconcile_managed_claim_mappings_in_tx(uow.conn(), &prepared).await?;
            self.append_all(&mut uow, batches).await?;
            uow.commit().await
        })
    }

    fn commit_oidc_issuers<'a>(
        &'a self,
        change: &'a OidcIssuerChange,
        batches: Vec<AppendEvents>,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;
            for issuer in &change.upserts {
                upsert_in_tx(uow.conn(), issuer).await?;
            }
            for name in &change.deletes {
                delete_by_name_in_tx(uow.conn(), name).await?;
            }
            self.append_all(&mut uow, batches).await?;
            uow.commit().await
        })
    }

    fn commit_upstream_mappings<'a>(
        &'a self,
        change: &'a UpstreamMappingCommit,
        batches: Vec<AppendEvents>,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;
            for mapping in &change.upserts {
                save_managed_in_tx(uow.conn(), mapping).await?;
            }
            for id in &change.deletes {
                delete_managed_by_id_in_tx(uow.conn(), *id).await?;
            }
            self.append_all(&mut uow, batches).await?;
            uow.commit().await
        })
    }

    fn commit_service_accounts<'a>(
        &'a self,
        change: &'a ServiceAccountCommit,
        batches: Vec<AppendEvents>,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;
            for sa in &change.upserts {
                upsert_service_account_in_tx(uow.conn(), sa).await?;
            }
            for name in &change.deletes {
                delete_service_account_by_name_in_tx(uow.conn(), name).await?;
            }
            self.append_all(&mut uow, batches).await?;
            uow.commit().await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time proof the adapter implements the port. Runtime
    /// invocation is covered by `tests/authority_audit_atomicity.rs`
    /// (the transaction needs a real server, and a `PgEventStore`
    /// cannot be constructed without one — its constructor probes the
    /// `events_immutable` trigger).
    #[test]
    fn pg_authority_lifecycle_implements_port() {
        fn _assert_port<T: AuthorityLifecyclePort>() {}
        _assert_port::<PgAuthorityLifecycle>();
    }
}
