//! Outbound port for `OidcIssuer` persistence (ADR 0018).
//!
//! `OidcIssuer` is CRUD (not event-sourced) — the apply use case
//! (`ApplyConfigUseCase::apply_oidc_issuers`) is the only writer, and
//! the federation branch on `/auth/token-exchange` is
//! the only read-heavy consumer.
//!
//! No `managed_by` field on the row (a deliberate design decision): the
//! aggregate is exclusively gitops-managed. The port therefore exposes
//! the four CRUD verbs the apply pipeline + federation handler need
//! and nothing else.

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

    /// INSERT-or-UPDATE keyed by `name`. The apply pipeline calls this
    /// on both `plan.create` and `plan.update`; the adapter UPSERTs so
    /// the row's primary key is stable across re-applies even if the
    /// caller-supplied `id` differs.
    fn upsert(&self, issuer: &OidcIssuer) -> BoxFuture<'_, DomainResult<()>>;

    /// DELETE by `name`. The apply pipeline calls this on `plan.delete`.
    /// A delete of a name that no longer exists is a no-op.
    fn delete_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<()>>;
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
