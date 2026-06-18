//! Outbound port for native API token persistence.
//!
//! Native API tokens are claimless static credentials (ADR 0012;
//! `docs/auth-catalog.md`). `find_by_prefix` is the validator hot path.
//!
//! # Adapter-side discipline (not enforced here)
//!
//! - `update_last_used` MUST persist a **bucketed** IP (`/24` IPv4, `/48`
//!   IPv6 — `hort_app::metrics::client_ip_bucket`) and MUST truncate the
//!   user-agent to **256 chars** at write — both are GDPR Art 5(1)(c) data
//!   minimisation requirements. A malformed input IP that fails to parse as
//!   `std::net::IpAddr` is stored verbatim — the validator is the upstream
//!   layer that filters those, and the adapter MUST NOT crash on a bad string.
//! - `revoke` is the natural transactional home for the
//!   `NOTIFY api_token_revocation, '<token_id>'` emission for
//!   multi-replica revocation invalidation. The LISTEN side lives in
//!   the token-validation use case; the NOTIFY emission is an adapter concern.
//! - `find_by_prefix` returns `Option<ApiToken>` on miss — the
//!   constant-time invariant lives in the use case, not in the
//!   adapter. A miss here MUST NOT log the prefix at WARN; DEBUG-level.

use uuid::Uuid;

use crate::entities::api_token::ApiToken;
use crate::error::DomainResult;
use crate::types::{Page, PageRequest};

use super::BoxFuture;

/// Outbound port for native API token persistence.
pub trait ApiTokenRepository: Send + Sync {
    /// Insert a new token row.
    ///
    /// The plaintext is hashed by the use case before this call lands; the
    /// adapter never sees plaintext. The input `token.token_hash` is the
    /// Argon2id PHC string.
    fn insert(&self, token: &ApiToken) -> BoxFuture<'_, DomainResult<()>>;

    /// Look up by 8-char body prefix.
    ///
    /// Returns `None` on miss — the constant-time-on-prefix-not-found
    /// invariant is the use case's concern, not the adapter's. A
    /// miss is `Ok(None)`, not `Err(NotFound)`.
    fn find_by_prefix(&self, prefix: &str) -> BoxFuture<'_, DomainResult<Option<ApiToken>>>;

    /// Look up by id (admin / list / revoke paths).
    ///
    /// Returns `Err(DomainError::NotFound)` when the id is unknown.
    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<ApiToken>>;

    /// List tokens for a given user (descending by `created_at`).
    fn list_for_user(
        &self,
        user_id: Uuid,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<ApiToken>>>;

    /// Update the debounced `last_used_*` columns.
    ///
    /// Adapter buckets `client_ip` via `hort_app::metrics::client_ip_bucket`
    /// (`/24` IPv4, `/48` IPv6) and truncates `user_agent` to 256 chars
    /// before writing. Implementations MUST NOT log the raw IP or UA.
    /// Inputs that fail to parse as `std::net::IpAddr` are written
    /// verbatim — the validator is the layer that rejects malformed
    /// strings; the adapter is best-effort and MUST NOT crash.
    fn update_last_used(
        &self,
        token_id: Uuid,
        at: chrono::DateTime<chrono::Utc>,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> BoxFuture<'_, DomainResult<()>>;

    /// Soft-revoke: set `revoked_at = NOW()` if not already set.
    ///
    /// Idempotent: returns `Ok(())` when the token is already revoked
    /// (the use case treats double-revoke as a no-op). The adapter is
    /// the natural home for the
    /// `NOTIFY api_token_revocation, '<token_id>'` emission used by
    /// multi-replica cache invalidation; the NOTIFY happens
    /// inside the same transaction as the UPDATE so cache drops cannot
    /// race with the revocation row.
    fn revoke(&self, token_id: Uuid) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time + runtime assertion that [`ApiTokenRepository`] is
    /// dyn-compatible. The architecture wires it behind
    /// `Arc<dyn ApiTokenRepository>` in the composition root; a
    /// non-dyn-compatible signature would break that wiring at compile
    /// time. The runtime `size_of` call exercises the assertion in the
    /// test body so coverage tooling counts it.
    #[test]
    fn _assert_dyn_compat() {
        let _ = size_of::<&dyn ApiTokenRepository>();
    }
}
