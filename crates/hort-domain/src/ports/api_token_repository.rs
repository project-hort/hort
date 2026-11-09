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
//! - `delete_expired_or_revoked_older_than` is the one method here whose
//!   statement removes a credential, and it MUST select a row on that
//!   row's **own** non-NULL mark. Both marks are nullable, a row with
//!   neither is a durable identity, and a `COALESCE`-flattened or negated
//!   predicate reaches it. The method's own docs carry the statement and
//!   the reasoning.

use std::time::Duration;

use uuid::Uuid;

use crate::entities::api_token::ApiToken;
use crate::error::{DomainError, DomainResult};
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

    /// Retention sweep for the credential store — delete rows that have
    /// been **expired or revoked** for longer than `horizon`, for every
    /// `kind`. Returns the number of rows deleted.
    ///
    /// ```sql
    /// DELETE FROM public.api_tokens
    ///  WHERE (expires_at IS NOT NULL AND expires_at < now() - $1::interval)
    ///     OR (revoked_at IS NOT NULL AND revoked_at < now() - $1::interval)
    /// ```
    ///
    /// **Each disjunct tests a row's own non-NULL mark, and that is the
    /// whole safety property.** `expires_at` and `revoked_at` are both
    /// nullable (`migrations/008_api_tokens.sql`), so a row with
    /// **neither** set is a durable identity that never expires. It
    /// satisfies neither disjunct and survives. An implementation must
    /// not flatten the two marks through `COALESCE`, and must not express
    /// the predicate as a negation of "still live": either form can
    /// answer `true` for a both-NULL row, and the row this statement
    /// reaches by mistake is a live credential. The explicit
    /// `IS NOT NULL` guards are redundant under SQL's three-valued logic
    /// — `NULL < anything` is already `NULL`, not `TRUE` — and are
    /// written anyway so the NULL reasoning is visible in the statement
    /// rather than being a property a reader has to recall.
    ///
    /// The horizon exists because the row carries `last_used_at`,
    /// `last_used_ip` and `last_used_user_agent`, which exist nowhere
    /// else in the system: the event store keeps `ApiTokenIssued`,
    /// `ApiTokenRevoked` and `ApiTokenUsed`, not those three fields. So
    /// the window is the decision that they are not worth keeping past
    /// it, which is why this is a horizon and not an immediate delete.
    ///
    /// **It deletes by state, never by provenance.** The statement must
    /// not consult `issued_via`: that column records which issuance path
    /// minted a row, and a sweep keyed on it would retain or discard
    /// credentials by origin rather than by whether they can still
    /// authenticate anybody.
    ///
    /// **One outbound effect.** `subscriptions.created_by_token_id`
    /// references `api_tokens(id) ON DELETE SET NULL`
    /// (`migrations/012_subscriptions.sql`), so this `DELETE` writes to
    /// another table. 012 blesses that for an operator deleting a token;
    /// it is harmless under an automated sweep only because no production
    /// path populates the column today — the one construction site writes
    /// `None`. A change that starts populating it makes this statement
    /// erase audit attribution.
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("delete_expired_or_revoked_older_than not implemented"))`
    /// rather than `Ok(0)`, so a fixture that has not opted in fails the
    /// sweep's tests loudly instead of reporting a successful sweep of
    /// nothing.
    fn delete_expired_or_revoked_older_than(
        &self,
        horizon: Duration,
    ) -> BoxFuture<'_, DomainResult<u64>> {
        let _ = horizon;
        Box::pin(async {
            Err(DomainError::Invariant(
                "delete_expired_or_revoked_older_than not implemented".into(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The narrowest possible implementor: it supplies only the six
    /// required methods, so every defaulted method on the trait is
    /// reached through it.
    struct Bare;

    impl ApiTokenRepository for Bare {
        fn insert(&self, _token: &ApiToken) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_prefix(&self, _prefix: &str) -> BoxFuture<'_, DomainResult<Option<ApiToken>>> {
            Box::pin(async { Ok(None) })
        }
        fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<ApiToken>> {
            Box::pin(async move {
                Err(DomainError::NotFound {
                    entity: "ApiToken",
                    id: id.to_string(),
                })
            })
        }
        fn list_for_user(
            &self,
            _user_id: Uuid,
            _page: PageRequest,
        ) -> BoxFuture<'_, DomainResult<Page<ApiToken>>> {
            Box::pin(async {
                Ok(Page {
                    items: Vec::new(),
                    total: 0,
                })
            })
        }
        fn update_last_used(
            &self,
            _token_id: Uuid,
            _at: chrono::DateTime<chrono::Utc>,
            _client_ip: Option<&str>,
            _user_agent: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn revoke(&self, _token_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// The retention sweep's default implementation surfaces
    /// `Invariant`, not `Ok(0)`.
    ///
    /// The distinction is the whole point of having a default at all. A
    /// default returning `Ok(0)` would let a fixture that never
    /// implemented the delete report a completed sweep of zero rows —
    /// indistinguishable, in the handler's `TaskOutcome::Completed`
    /// summary and in its tests, from a database that genuinely had no
    /// eligible row. Mirrors
    /// `JobsRepository::delete_terminal_scan_rows_older_than`'s default
    /// and the reasoning recorded there.
    #[tokio::test]
    async fn delete_expired_or_revoked_default_impl_returns_invariant_error() {
        let repo: Box<dyn ApiTokenRepository> = Box::new(Bare);
        let err = repo
            .delete_expired_or_revoked_older_than(Duration::from_secs(90 * 24 * 60 * 60))
            .await
            .expect_err("the default implementation must not report a successful sweep");
        let DomainError::Invariant(message) = err else {
            panic!("expected Invariant, got {err:?}");
        };
        assert!(
            message.contains("delete_expired_or_revoked_older_than"),
            "the message must name the unimplemented method: {message}"
        );
    }

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
