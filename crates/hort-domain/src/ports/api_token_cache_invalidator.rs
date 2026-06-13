//! Outbound port for invalidating cached PAT validations.
//!
//! Multi-replica revocation invalidation (ADR 0012): this trait is
//! consumed by the in-process `PatCache` validator path; the Postgres
//! `LISTEN/NOTIFY` adapter calls these methods
//! when a `revoke()` / user-deactivation lands on any replica.
//!
//! # Why a trait, not a concrete type
//!
//! The composition root holds the `Arc<PatCache>` (the only production
//! implementation today) but the **listener task** in `hort-server` needs
//! to call `invalidate_*` without statically depending on `hort-app`'s
//! internal cache type — the listener is wired against `Arc<dyn
//! ApiTokenCacheInvalidator>` so the cache implementation is swappable
//! and the dep graph stays one-way (server → app, not the other way
//! around).
//!
//! # Method semantics
//!
//! - `invalidate_token(token_id)` — drop the single cache entry whose
//!   `ApiTokenValidation.token_id == token_id`. The cache resolves this
//!   via a reverse `token_id → cache_key` index (see `PatCache`'s
//!   dual-index strategy). Unknown id is a noop.
//! - `invalidate_user(user_id)` — drop **every** cache entry whose
//!   `ApiTokenValidation.user_id == user_id`. Used on user
//!   deactivation (`users.is_active = false` flip). O(N) walk; the
//!   cache is bounded (default 10k entries).
//! - `drop_all()` — clear the entire cache. Called on listener
//!   reconnect — if `LISTEN` died and was rebuilt, we cannot prove the
//!   cache is consistent with the database, so we drop everything and
//!   pay the rewarm cost.
//!
//! All three methods are **synchronous** and **non-blocking** — the
//! cache uses an in-process `Mutex`, so `Send + Sync` is the only
//! threading bound. The listener task drives them from a `tokio` task
//! but never awaits.

use uuid::Uuid;

/// Outbound port for invalidating cached PAT validations on revocation
/// or user-deactivation events. See module docs for semantics.
pub trait ApiTokenCacheInvalidator: Send + Sync {
    /// Drop the single cache entry for `token_id`. Noop on unknown id.
    fn invalidate_token(&self, token_id: Uuid);

    /// Drop every cache entry whose `user_id` matches.
    fn invalidate_user(&self, user_id: Uuid);

    /// Clear the entire cache. Called on listener reconnect.
    fn drop_all(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time + runtime assertion that
    /// [`ApiTokenCacheInvalidator`] is dyn-compatible. The composition
    /// root wires it behind `Arc<dyn ApiTokenCacheInvalidator>`; a
    /// non-dyn-compatible signature would break that wiring at compile
    /// time. The runtime `size_of` call exercises the assertion in the
    /// test body so coverage tooling counts it.
    #[test]
    fn _assert_dyn_compat() {
        let _ = size_of::<&dyn ApiTokenCacheInvalidator>();
    }
}
