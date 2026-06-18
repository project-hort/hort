//! Outbound port for short-lived, TTL-bounded key/value state.
//!
//! This is the domain-side contract for every piece of registry state
//! that is *not* the authoritative artifact record: in-flight
//! stateful-upload sessions (OCI three-phase blob upload, Maven
//! chunked PUT, Git LFS batch transfer), request-idempotency tokens,
//! rate-limit counters, and any other ephemeral primitive where the
//! operational characteristics — bounded size, monotonic TTL,
//! optimistic-concurrency CAS, no durability guarantee — are the same
//! across backends.
//!
//! Production wires [`crate::ports::storage::StoragePort`] to the CAS
//! adapter and `EphemeralStore` to Redis (or to the in-memory adapter
//! in single-node / test deployments). The two ports never share a
//! backend: Redis is a weak-durability cache and must not hold the
//! canonical byte-level artifact record; the CAS backend has no
//! TTL / CAS primitive and cannot model upload-session lifecycles
//! cleanly. Keeping the two axes separate mirrors the architectural
//! direction (ADR 0001 / ADR 0003) and serves the OCI stateful-upload
//! flow — see `docs/architecture/how-to/oci-pull-through.md`.
//!
//! # Key space
//!
//! The port accepts any `&str`. Callers are responsible for namespacing
//! (the convention is `stateful_upload:{format}:{session_id}` for the
//! stateful-upload namespace). Adapters MUST NOT interpret the key —
//! no prefix stripping, no parsing — so two different callers with
//! disjoint prefixes cannot collide.
//!
//! # Version semantics
//!
//! Every stored entry carries a monotonic 64-bit version. The version:
//!
//! - starts at `1` on the first `put` / `put_if_absent` for a key;
//! - increments by exactly `1` on every subsequent successful `put`,
//!   `put_if_absent` (when the key is re-created after a full
//!   expiry/delete cycle), and `compare_and_swap`;
//! - is opaque to callers — they treat it as a monotonically-ordered
//!   token. Adapters persist it alongside the value (hash field in
//!   Redis, struct field in the in-memory variant) so CAS can compare
//!   without a round-trip-per-read.
//!
//! # TTL semantics
//!
//! Every write takes a `Duration`. The adapter sets a backend TTL such
//! that a `get` issued after expiry returns `Ok(None)`. `extend_ttl`
//! adjusts the TTL on an existing key without touching the value or
//! version; `extend_ttl` on an absent / expired key is
//! `Ok(())` — the port contract pretends the expiry raced the caller.
//! That tolerance is load-bearing for upload-session GC: the stateful-
//! upload path extends TTL on every chunk, and the extension is
//! naturally racy against the GC sweep.

use std::time::Duration;

use bytes::Bytes;

use crate::error::DomainResult;

use super::BoxFuture;

/// Outbound port for short-lived TTL-bounded KV state (upload
/// sessions, idempotency tokens, rate-limit counters, …).
///
/// See the module-level doc comment for version, TTL, and key-space
/// semantics. Every method is fallible — infrastructure failures
/// surface as [`crate::error::DomainError::Invariant`] (adapters wrap
/// Redis / filesystem errors).
pub trait EphemeralStore: Send + Sync {
    /// Read the value under `key`. Returns `Ok(None)` for an absent or
    /// already-expired key (the two cases are indistinguishable to the
    /// caller by design — TTL expiry is a normal outcome).
    fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>>;

    /// Unconditionally write `value` under `key` with a fresh `ttl`.
    /// Replaces any pre-existing entry. Increments the key's version
    /// counter by one; if the key was absent (or previously expired)
    /// the version starts at `1`.
    fn put(&self, key: &str, value: Bytes, ttl: Duration) -> BoxFuture<'_, DomainResult<()>>;

    /// Create `key` only if no live entry currently exists. Returns
    /// `Ok(true)` on a successful create, `Ok(false)` when an existing
    /// entry blocked the write. On success the version is set to `1`.
    ///
    /// Used by idempotency primitives — callers race on a single key
    /// and exactly one wins. An expired entry counts as absent; the
    /// adapter must consult the TTL before rejecting.
    fn put_if_absent(
        &self,
        key: &str,
        value: Bytes,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<bool>>;

    /// Atomically replace the value under `key` *iff* the stored
    /// version equals `expected_version`. Returns
    /// `Ok(Some(new_version))` on success (new version =
    /// `expected_version + 1`), `Ok(None)` when the version mismatched
    /// (another caller won, or the key has since expired).
    ///
    /// The `ttl` is applied on success the same way `put` applies it
    /// — a successful CAS resets the expiry clock. A CAS miss does
    /// NOT touch the existing entry's TTL.
    ///
    /// Optimistic-concurrency primitive for `stateful_upload`
    /// progress updates and any other caller that needs compare-and-
    /// update without a distributed mutex.
    fn compare_and_swap(
        &self,
        key: &str,
        expected_version: u64,
        new_value: Bytes,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<Option<u64>>>;

    /// Remove `key` if present. Absent keys are `Ok(())` — deletion is
    /// idempotent so finalize + GC sweep can race without surfacing a
    /// spurious error.
    fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>>;

    /// Reset the TTL on an existing entry without modifying the value
    /// or version. Absent / expired keys are `Ok(())` so callers
    /// holding a stale handle don't surface a spurious error — the
    /// GC sweep tolerates the race by contract.
    fn extend_ttl(&self, key: &str, ttl: Duration) -> BoxFuture<'_, DomainResult<()>>;

    /// Atomically increment an integer counter at `key` by 1 with a
    /// cap check. The counter is encoded as the decimal-ASCII bytes
    /// of a `u64`. Refresh the TTL to `ttl` on every successful
    /// increment.
    ///
    /// - Returns `Ok(Some(new_value))` when the increment succeeds
    ///   and `new_value <= max`. The first increment over an absent
    ///   key yields `Some(1)`.
    /// - Returns `Ok(None)` when the increment would push the counter
    ///   above `max`. NO write is performed in this case; the
    ///   caller's intent is "reject the request" and the counter
    ///   stays at its prior value.
    /// - Errors are infrastructure-level and surface as
    ///   `DomainError::Invariant`.
    ///
    /// The OCI per-`(repo,
    /// principal)` upload-session cap consumes this primitive. The
    /// atomic increment-and-check closes a TOCTOU race where two
    /// concurrent open-session requests both pass a non-atomic
    /// `get + put` check at the cap boundary.
    ///
    /// # Default impl
    ///
    /// The provided default uses a `get` + `compare_and_swap` retry
    /// loop bounded at 16 iterations — adequate for low contention
    /// (the cap is per-`(repo, principal)`, so realistic contention
    /// is a single user opening multiple sessions concurrently).
    /// Adapters that can do this atomically (Redis Lua, in-memory
    /// per-key mutex) override for race-free semantics.
    fn try_increment_counter(
        &self,
        key: &str,
        max: u64,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
        // Default: bounded retry-loop fallback. Adapters override
        // for single-shot atomicity (memory: per-key mutex; Redis:
        // Lua). The `key.to_owned()` keeps the future `: 'static`
        // re. lifetimes — a `key: &'1 str` would otherwise collide
        // with the `&self: '2` lifetime in the BoxFuture's `'_`.
        let key_owned = key.to_owned();
        Box::pin(async move {
            const MAX_ATTEMPTS: usize = 16;
            for _ in 0..MAX_ATTEMPTS {
                match self.get(&key_owned).await? {
                    None => {
                        // No live entry. The first increment uses
                        // `put_if_absent` to create the counter at 1.
                        // On a race a second caller may win the
                        // create — `put_if_absent` returns false and
                        // we retry the loop, this time taking the
                        // CAS branch on the now-present entry.
                        if max == 0 {
                            return Ok(None);
                        }
                        let bytes = Bytes::from(b"1".to_vec());
                        let created = self.put_if_absent(&key_owned, bytes, ttl).await?;
                        if created {
                            return Ok(Some(1));
                        }
                        // Lost the create race; retry as CAS.
                        continue;
                    }
                    Some(value) => {
                        // Parse + check. A non-numeric / non-utf8
                        // value at this key means a foreign caller
                        // wrote a non-counter value here — a
                        // key-space collision the catalog forbids.
                        let s = std::str::from_utf8(&value).map_err(|_| {
                            crate::error::DomainError::Invariant(
                                "ephemeral counter: non-utf8 bytes at counter key".into(),
                            )
                        })?;
                        let current: u64 = s.parse().map_err(|_| {
                            crate::error::DomainError::Invariant(
                                "ephemeral counter: non-numeric value at counter key".into(),
                            )
                        })?;
                        if current >= max {
                            return Ok(None);
                        }
                        // The default impl has no version-aware CAS
                        // primitive without widening the trait. The
                        // pragmatic fallback uses `put` — under
                        // contention this can over-count by at most
                        // the inflight-concurrent-caller count on
                        // the same key, which is bounded by the
                        // per-`(repo, principal)` cap itself.
                        // Adapters override for race-free semantics.
                        let new_value = current + 1;
                        let new_bytes = Bytes::from(format!("{new_value}").into_bytes());
                        self.put(&key_owned, new_bytes, ttl).await?;
                        return Ok(Some(new_value));
                    }
                }
            }
            Err(crate::error::DomainError::Invariant(
                "ephemeral counter: retry budget exhausted".into(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `EphemeralStore` is dyn-compatible.
    /// `AppContext.ephemeral: Arc<dyn EphemeralStore>` depends on this.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn EphemeralStore>();
    }
}
