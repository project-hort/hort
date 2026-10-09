//! Outbound port for `OidcIssuer` persistence (ADR 0018).
//!
//! `OidcIssuer` is CRUD (not event-sourced) — the apply use case
//! (`ApplyConfigUseCase::apply_oidc_issuers`) is the only writer, and
//! the federation branch on `/auth/token-exchange` is
//! the only read-heavy consumer.
//!
//! No `managed_by` field on the row (a deliberate design decision): the
//! aggregate is exclusively gitops-managed.
//!
//! **This port is read-only.** The write is
//! [`AuthorityLifecyclePort::commit_oidc_issuers`], which commits the
//! upsert/delete set **and** the attesting `OidcIssuerCreated` /
//! `OidcIssuerUpdated` / `OidcIssuerDeleted` events in one
//! transaction. That matters more here than anywhere else in the
//! family: an issuer row is a trust anchor, and a serving validator
//! reads this repository at validation time, so a surviving replica
//! acts on the new trust state the moment the row commits. See
//! [`crate::ports::permission_grant_repository`] for why the write
//! methods are *removed* from this trait rather than left unused.
//!
//! [`AuthorityLifecyclePort::commit_oidc_issuers`]:
//!     crate::ports::authority_lifecycle::AuthorityLifecyclePort::commit_oidc_issuers

use crate::entities::oidc_issuer::OidcIssuer;
use crate::error::DomainResult;

use super::BoxFuture;

/// Persistence port for the `oidc_issuers` table.
///
/// Implementations live in `hort-adapters-postgres::oidc_issuer_repo`.
pub trait OidcIssuerRepository: Send + Sync {
    /// Every declared issuer. The apply pipeline reads this to build
    /// the current-snapshot view for the diff; bounded by the operator's
    /// CRD count (typically <50).
    fn list(&self) -> BoxFuture<'_, DomainResult<Vec<OidcIssuer>>>;

    /// Lookup by the CRD `metadata.name`. Returns `None` when no issuer
    /// with that name exists. Used by the apply path's resolve step.
    fn get_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<Option<OidcIssuer>>>;

    /// Lookup by the canonical `iss` claim value. Used by the federation
    /// branch on `/auth/token-exchange` to resolve a
    /// foreign JWT's `iss` to the validator config.
    fn get_by_issuer_url(&self, url: &str) -> BoxFuture<'_, DomainResult<Option<OidcIssuer>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `OidcIssuerRepository` is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn OidcIssuerRepository>();
    }
}
