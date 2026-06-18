//! In-process PAT validation cache.
//!
//! Part of the native API-token surface (ADR 0012). The cache is
//! per-replica, in-process, bounded LRU with a wall-clock TTL. The
//! validator populates it after a successful Argon2 verify; the
//! Postgres `LISTEN/NOTIFY` listener drives invalidation through
//! the [`ApiTokenCacheInvalidator`] port.
//!
//! # Anti-patterns guarded against here
//!
//! - **No negative caching.** `prefix_not_found` and `hash_mismatch`
//!   re-run the constant-time path on every call. Caching either would
//!   be a timing oracle (cache hit vs cache miss is itself observable).
//!   This module simply does not expose a "store-negative" surface.
//! - **No async API.** All operations are sync `Mutex`-guarded so they
//!   compose cleanly with the LISTEN/NOTIFY listener task (which polls
//!   on a `tokio` runtime but never awaits the cache itself). Cache
//!   ops are O(1) for `get` / `insert` / `invalidate_token` and O(N)
//!   for `invalidate_user` / `drop_all`; the bound (default 10k) keeps
//!   the walk cheap.
//! - **Clock injection, not `tokio::time::sleep` in tests.** The TTL
//!   is driven by a [`Clock`] trait so tests can advance virtual time
//!   without runtime sleeps.
//!
//! # Dual-index strategy
//!
//! ```text
//!   primary  : LruCache<CacheKey, CachedEntry>     (eviction, TTL)
//!   reverse  : HashMap<Uuid, CacheKey>             (token_id lookup)
//! ```
//!
//! The reverse index is the only mutable companion of the LRU. The two
//! must stay consistent: every `insert` writes to both; every `evict`
//! / `invalidate` removes from both. The `cache_dual_index_consistency`
//! test pins this invariant.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use lru::LruCache;
use uuid::Uuid;

use hort_domain::entities::api_token::{TokenCap, TokenKind};
use hort_domain::ports::api_token_cache_invalidator::ApiTokenCacheInvalidator;

// ---------------------------------------------------------------------------
// CacheKey
// ---------------------------------------------------------------------------

/// SHA-256 of the full plaintext token (`hort_<kind>_<body>`). The cache
/// keys on this digest, never the plaintext, so a memory disclosure does
/// not leak issuable tokens (the plaintext is one preimage step away,
/// equivalent to the on-disk Argon2id hash).
///
/// Newtype around `[u8; 32]` so callers cannot accidentally pass a raw
/// slice or a `Vec<u8>` of the wrong length. Construction is explicit —
/// the validator will compute the digest and call
/// [`CacheKey::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheKey([u8; 32]);

impl CacheKey {
    /// Wrap a raw 32-byte SHA-256 digest. The validator computes this
    /// from the full plaintext on the cache-lookup path.
    pub fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }
}

// ---------------------------------------------------------------------------
// ApiTokenValidation — the cached payload
// ---------------------------------------------------------------------------

/// The fields a cached PAT validation carries forward.
///
/// Intentionally minimal — anything not needed by the auth-middleware
/// hot path stays out (the `token_hash`, `token_prefix`,
/// `last_used_*` columns are repository-only). The validator
/// re-checks `expires_at` and `revoked_at` on every cache hit so a
/// token that expires mid-cache-TTL is still rejected without a round
/// trip — see the cache-hit fast path ("Cache hit + non-revoked +
/// non-expired → return cached").
///
/// Eq/PartialEq are derived for test convenience (assert a cached
/// value round-trips); the field set carries no cryptographic
/// material so derivation is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiTokenValidation {
    /// `api_tokens.id` — used by the reverse index for
    /// `invalidate_token`.
    pub token_id: Uuid,
    /// `users.id` — used by `invalidate_user` for the
    /// user-deactivation broadcast.
    pub user_id: Uuid,
    /// Token-flavour discriminator. Threaded
    /// from the underlying `api_tokens.kind` column so
    /// `authenticate_pat` can inject the matching role marker
    /// (`"cli_session"` / `"service_account"`) into `principal.roles`.
    /// `Pat` adds no marker (the wire default).
    pub kind: TokenKind,
    /// The cap fixed at issuance. The validator AND-intersects this
    /// with the user's live RBAC grants on every authz check.
    pub token_cap: TokenCap,
    /// Mid-cache-TTL expiry check. `None` for unbounded
    /// service-account tokens (`HORT_TOKEN_ALLOW_UNBOUNDED_SVC=true`).
    pub expires_at: Option<DateTime<Utc>>,
    /// Mid-cache-TTL revocation check. The LISTEN/NOTIFY path is the
    /// fast invalidator; this field is the fallback so a stuck
    /// listener can never serve a revoked token past the next read.
    pub revoked_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// Wall-clock abstraction. Production wires [`SystemClock`]; tests
/// inject a `MockClock` that advances on demand so the 5-min TTL is
/// testable without `tokio::time::sleep`.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// Production clock — `chrono::Utc::now()`.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

// ---------------------------------------------------------------------------
// PatCache
// ---------------------------------------------------------------------------

/// One stored entry. `inserted_at` drives the TTL check on `get`; the
/// LRU itself drives capacity-based eviction.
#[derive(Debug, Clone)]
struct CachedEntry {
    validation: ApiTokenValidation,
    inserted_at: DateTime<Utc>,
}

/// Inner mutable state. Single `Mutex` guards both halves of the
/// dual-index. `RwLock` would only buy us concurrent-readers, but the
/// LRU's `get` mutates the recency order — every read is a write under
/// the hood. So `Mutex` is the correct primitive; documented per the
/// architect-skill checklist.
struct Inner {
    /// Primary index: `CacheKey → CachedEntry`. Eviction order = LRU.
    primary: LruCache<CacheKey, CachedEntry>,
    /// Reverse index: `token_id → CacheKey`. Kept consistent with
    /// `primary` on every mutation.
    reverse: HashMap<Uuid, CacheKey>,
}

/// In-process PAT validation cache. See module docs.
pub struct PatCache {
    inner: Mutex<Inner>,
    ttl: Duration,
    clock: Box<dyn Clock>,
}

impl PatCache {
    /// Build a cache with the given capacity (default 10k per
    /// `HORT_PAT_CACHE_SIZE`) and TTL (default 5 min per `HORT_PAT_CACHE_TTL_SECS`),
    /// using [`SystemClock`].
    ///
    /// `capacity` is clamped to `1` if `0` is supplied — `lru::LruCache`
    /// requires `NonZeroUsize`; treating `0` as a request for the
    /// minimum is gentler than a panic at startup.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self::new_with_clock(capacity, ttl, Box::new(SystemClock))
    }

    /// Build with an injected clock — production calls [`Self::new`];
    /// tests pass a `MockClock`.
    pub fn new_with_clock(capacity: usize, ttl: Duration, clock: Box<dyn Clock>) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("clamped to >= 1");
        Self {
            inner: Mutex::new(Inner {
                primary: LruCache::new(cap),
                reverse: HashMap::new(),
            }),
            ttl,
            clock,
        }
    }

    /// Cache lookup. Returns `None` on miss, on TTL-expiry (the
    /// expired entry is evicted as a side-effect), or on any internal
    /// poison condition.
    pub fn get(&self, cache_key: &CacheKey) -> Option<ApiTokenValidation> {
        let now = self.clock.now();
        let mut guard = self.inner.lock().ok()?;
        // Peek first to avoid bumping LRU recency on an expired hit.
        let expired = match guard.primary.peek(cache_key) {
            Some(entry) => {
                let age = now.signed_duration_since(entry.inserted_at);
                // `to_std()` fails for negative durations — clock skew
                // backward. Treat that as "not expired" (we refuse to
                // reason about a clock running backwards) so the entry
                // survives until either capacity-evicted or
                // explicit-invalidated.
                match age.to_std() {
                    Ok(age) => age > self.ttl,
                    Err(_) => false,
                }
            }
            None => return None,
        };
        if expired {
            // Side-effect eviction. Both halves of the dual-index get
            // cleaned so a future `insert` for the same id is unambiguous.
            if let Some(entry) = guard.primary.pop(cache_key) {
                guard.reverse.remove(&entry.validation.token_id);
            }
            return None;
        }
        // Live entry — `get` (not `peek`) so the LRU recency is bumped.
        guard
            .primary
            .get(cache_key)
            .map(|entry| entry.validation.clone())
    }

    /// Insert (or replace) a cache entry. Updates both indices.
    /// Capacity-eviction of the LRU's tail also cleans the reverse
    /// index — `lru::LruCache::push` returns the evicted `(key, value)`
    /// when it overflows, which we use to drop the matching reverse
    /// entry.
    pub fn insert(&self, cache_key: CacheKey, validation: ApiTokenValidation) {
        let now = self.clock.now();
        let Ok(mut guard) = self.inner.lock() else {
            // Poisoned mutex — a previous panic with the lock held.
            // Do not silently corrupt the cache; the next caller will
            // see `None` for everything and refill from upstream.
            return;
        };
        let token_id = validation.token_id;

        // If a different cache_key already maps to this token_id (e.g.
        // the validator re-derived a digest after a hash rotation),
        // remove the old primary entry so the reverse index has a
        // single source of truth.
        if let Some(old_key) = guard.reverse.get(&token_id).copied() {
            if old_key != cache_key {
                guard.primary.pop(&old_key);
            }
        }

        let entry = CachedEntry {
            validation,
            inserted_at: now,
        };
        let evicted = guard.primary.push(cache_key, entry);
        guard.reverse.insert(token_id, cache_key);

        if let Some((evicted_key, evicted_entry)) = evicted {
            // `push` returns `Some` either when an existing key was
            // overwritten (key == cache_key) or when capacity-eviction
            // dropped the oldest. We only want to clean the reverse
            // index for the capacity-eviction case AND only if the
            // evicted token_id isn't the one we just (re-)inserted.
            if evicted_key != cache_key && evicted_entry.validation.token_id != token_id {
                guard.reverse.remove(&evicted_entry.validation.token_id);
            }
        }
    }
}

impl ApiTokenCacheInvalidator for PatCache {
    fn invalidate_token(&self, token_id: Uuid) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        if let Some(cache_key) = guard.reverse.remove(&token_id) {
            guard.primary.pop(&cache_key);
        }
    }

    fn invalidate_user(&self, user_id: Uuid) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        // Walk the primary, collect matching keys, then drop. Two-pass
        // because `LruCache::iter` borrows immutably and the removals
        // must not invalidate the iterator.
        let to_drop: Vec<(CacheKey, Uuid)> = guard
            .primary
            .iter()
            .filter(|(_, entry)| entry.validation.user_id == user_id)
            .map(|(k, e)| (*k, e.validation.token_id))
            .collect();
        for (cache_key, token_id) in to_drop {
            guard.primary.pop(&cache_key);
            guard.reverse.remove(&token_id);
        }
    }

    fn drop_all(&self) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        guard.primary.clear();
        guard.reverse.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::entities::rbac::Permission;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::thread;

    // -----------------------------------------------------------------
    // MockClock — tests advance virtual time without runtime sleeps.
    // -----------------------------------------------------------------

    struct MockClock {
        now: StdMutex<DateTime<Utc>>,
    }

    impl MockClock {
        fn new(start: DateTime<Utc>) -> Arc<Self> {
            Arc::new(Self {
                now: StdMutex::new(start),
            })
        }

        fn advance(&self, by: Duration) {
            let mut g = self.now.lock().unwrap();
            *g += chrono::Duration::from_std(by).expect("test duration fits");
        }
    }

    impl Clock for Arc<MockClock> {
        fn now(&self) -> DateTime<Utc> {
            *self.now.lock().unwrap()
        }
    }

    fn t0() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("fixed epoch")
    }

    fn cap() -> TokenCap {
        TokenCap {
            permissions: vec![Permission::Read],
            repository_ids: None,
        }
    }

    fn validation(token_id: Uuid, user_id: Uuid) -> ApiTokenValidation {
        ApiTokenValidation {
            token_id,
            user_id,
            kind: TokenKind::Pat,
            token_cap: cap(),
            expires_at: None,
            revoked_at: None,
        }
    }

    fn key(byte: u8) -> CacheKey {
        CacheKey::new([byte; 32])
    }

    fn cache_with_clock(capacity: usize, ttl: Duration, clock: Arc<MockClock>) -> PatCache {
        PatCache::new_with_clock(capacity, ttl, Box::new(clock))
    }

    // -----------------------------------------------------------------
    // Acceptance tests
    // -----------------------------------------------------------------

    #[test]
    fn cache_get_returns_none_on_miss() {
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock);
        assert_eq!(cache.get(&key(1)), None);
    }

    #[test]
    fn cache_get_returns_some_after_insert() {
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock);
        let v = validation(Uuid::new_v4(), Uuid::new_v4());
        cache.insert(key(1), v.clone());
        assert_eq!(cache.get(&key(1)), Some(v));
    }

    #[test]
    fn cache_evicts_oldest_when_capacity_reached() {
        // capacity=2, insert 3 distinct keys → key(1) is evicted (LRU
        // tail) and the reverse index for its token_id is cleaned.
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(2, Duration::from_secs(300), clock);
        let v1 = validation(Uuid::new_v4(), Uuid::new_v4());
        let v2 = validation(Uuid::new_v4(), Uuid::new_v4());
        let v3 = validation(Uuid::new_v4(), Uuid::new_v4());
        cache.insert(key(1), v1.clone());
        cache.insert(key(2), v2.clone());
        cache.insert(key(3), v3.clone());
        assert_eq!(cache.get(&key(1)), None, "oldest evicted");
        assert_eq!(cache.get(&key(2)), Some(v2));
        assert_eq!(cache.get(&key(3)), Some(v3));
    }

    #[test]
    fn cache_ttl_expires_entry() {
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock.clone());
        let v = validation(Uuid::new_v4(), Uuid::new_v4());
        cache.insert(key(1), v);
        clock.advance(Duration::from_secs(301));
        assert_eq!(cache.get(&key(1)), None, "5-min TTL + 1s expires");
    }

    #[test]
    fn cache_ttl_does_not_expire_within_window() {
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock.clone());
        let v = validation(Uuid::new_v4(), Uuid::new_v4());
        cache.insert(key(1), v.clone());
        clock.advance(Duration::from_secs(299));
        assert_eq!(cache.get(&key(1)), Some(v));
    }

    #[test]
    fn cache_invalidate_token_drops_specific_entry() {
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock);
        let token_a = Uuid::new_v4();
        let token_b = Uuid::new_v4();
        let user = Uuid::new_v4();
        let va = validation(token_a, user);
        let vb = validation(token_b, user);
        cache.insert(key(1), va);
        cache.insert(key(2), vb.clone());

        cache.invalidate_token(token_a);

        assert_eq!(cache.get(&key(1)), None);
        assert_eq!(cache.get(&key(2)), Some(vb), "untouched entry survives");
    }

    #[test]
    fn cache_invalidate_token_unknown_id_is_noop() {
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock);
        let v = validation(Uuid::new_v4(), Uuid::new_v4());
        cache.insert(key(1), v.clone());

        cache.invalidate_token(Uuid::new_v4()); // unknown id

        assert_eq!(cache.get(&key(1)), Some(v), "noop preserves entry");
    }

    #[test]
    fn cache_invalidate_user_drops_all_for_that_user() {
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock);
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        let va1 = validation(Uuid::new_v4(), user_a);
        let va2 = validation(Uuid::new_v4(), user_a);
        let vb1 = validation(Uuid::new_v4(), user_b);
        cache.insert(key(1), va1);
        cache.insert(key(2), va2);
        cache.insert(key(3), vb1.clone());

        cache.invalidate_user(user_a);

        assert_eq!(cache.get(&key(1)), None);
        assert_eq!(cache.get(&key(2)), None);
        assert_eq!(cache.get(&key(3)), Some(vb1), "user_b survives");
    }

    #[test]
    fn cache_drop_all_clears_everything() {
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock);
        cache.insert(key(1), validation(Uuid::new_v4(), Uuid::new_v4()));
        cache.insert(key(2), validation(Uuid::new_v4(), Uuid::new_v4()));

        cache.drop_all();

        assert_eq!(cache.get(&key(1)), None);
        assert_eq!(cache.get(&key(2)), None);
    }

    #[test]
    fn cache_dual_index_consistency() {
        // After invalidate_token, BOTH the LRU primary AND the
        // reverse index must be clean — a leftover reverse entry
        // would let a re-insert under a NEW cache_key silently drop
        // the new entry through the "old_key != cache_key" branch.
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock);
        let token_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        cache.insert(key(1), validation(token_id, user_id));

        cache.invalidate_token(token_id);

        {
            let guard = cache.inner.lock().unwrap();
            assert!(guard.primary.peek(&key(1)).is_none(), "primary clean");
            assert!(
                !guard.reverse.contains_key(&token_id),
                "reverse index clean"
            );
        }

        // Re-insert under a new key — the entry must be visible.
        let v2 = validation(token_id, user_id);
        cache.insert(key(2), v2.clone());
        assert_eq!(cache.get(&key(2)), Some(v2));
    }

    #[test]
    fn cache_concurrent_access_does_not_panic() {
        // 8 threads × 100 ops, exercising insert / get /
        // invalidate_token / invalidate_user / drop_all in
        // parallel. The cache is sync (`std::sync::Mutex`), so we
        // use `std::thread`, NOT `tokio::spawn`. The assertion is
        // the negative one: no panic, no poison.
        let clock = MockClock::new(t0());
        let cache = Arc::new(cache_with_clock(32, Duration::from_secs(300), clock));
        let mut handles = Vec::new();
        for thread_idx in 0..8u8 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for op in 0..100u8 {
                    let k = key(thread_idx ^ op);
                    let token_id = Uuid::new_v4();
                    let user_id = Uuid::new_v4();
                    match op % 5 {
                        0 => cache.insert(k, validation(token_id, user_id)),
                        1 => {
                            let _ = cache.get(&k);
                        }
                        2 => cache.invalidate_token(token_id),
                        3 => cache.invalidate_user(user_id),
                        _ => cache.drop_all(),
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("no panic");
        }
        // Still usable afterwards — final smoke insert/get round-trip.
        let v = validation(Uuid::new_v4(), Uuid::new_v4());
        cache.insert(key(0xff), v.clone());
        assert_eq!(cache.get(&key(0xff)), Some(v));
    }

    #[test]
    fn _assert_dyn_compat() {
        // `&PatCache` coerces to `&dyn ApiTokenCacheInvalidator` —
        // this is the wiring the composition root depends on.
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock);
        let _: &dyn ApiTokenCacheInvalidator = &cache;
    }

    // -----------------------------------------------------------------
    // Implementation-detail coverage — the branches above don't all
    // exercise every match arm. These pin the remaining ones.
    // -----------------------------------------------------------------

    #[test]
    fn cache_insert_replaces_under_same_key() {
        // Same `cache_key`, same `token_id` — the second insert
        // overwrites and the `inserted_at` resets so TTL effectively
        // restarts.
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock.clone());
        let token_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let v1 = validation(token_id, user_id);
        cache.insert(key(1), v1);

        clock.advance(Duration::from_secs(200));
        let v2 = ApiTokenValidation {
            revoked_at: Some(t0()),
            ..validation(token_id, user_id)
        };
        cache.insert(key(1), v2.clone());

        // Step past where the original would have expired (>300s
        // total) but only 150s after the replacement.
        clock.advance(Duration::from_secs(150));
        assert_eq!(
            cache.get(&key(1)),
            Some(v2),
            "replacement reset the TTL window"
        );
    }

    #[test]
    fn cache_insert_drops_stale_primary_under_old_key_when_token_id_remaps() {
        // token_id maps to key(1). Caller re-inserts SAME token_id
        // under key(2) (e.g. plaintext rotated mid-session). The
        // old primary entry under key(1) must be dropped, the new
        // one under key(2) must be live, and the reverse index
        // must point to key(2).
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock);
        let token_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        cache.insert(key(1), validation(token_id, user_id));
        let v2 = validation(token_id, user_id);
        cache.insert(key(2), v2.clone());

        assert_eq!(cache.get(&key(1)), None, "old key dropped");
        assert_eq!(cache.get(&key(2)), Some(v2));
        let guard = cache.inner.lock().unwrap();
        assert_eq!(guard.reverse.get(&token_id), Some(&key(2)));
    }

    #[test]
    fn cache_negative_clock_skew_keeps_entry() {
        // If the wall clock jumps backward (operator NTP correction,
        // VM time travel), `signed_duration_since` is negative and
        // `to_std()` errors. The entry must survive — we refuse to
        // expire on a clock running backwards. Capacity-eviction
        // and explicit `invalidate_*` are the only ways out.
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(8, Duration::from_secs(300), clock.clone());
        let v = validation(Uuid::new_v4(), Uuid::new_v4());
        cache.insert(key(1), v.clone());
        // Step backward by 1 hour.
        {
            let mut g = clock.now.lock().unwrap();
            *g -= chrono::Duration::hours(1);
        }
        assert_eq!(cache.get(&key(1)), Some(v));
    }

    #[test]
    fn cache_capacity_zero_clamps_to_one() {
        // `LruCache::new` panics on `NonZeroUsize::new(0)`. We clamp
        // to 1 so an `HORT_PAT_CACHE_SIZE=0` misconfig boots cleanly
        // (effectively disabled — every insert evicts the previous).
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(0, Duration::from_secs(300), clock);
        let v1 = validation(Uuid::new_v4(), Uuid::new_v4());
        let v2 = validation(Uuid::new_v4(), Uuid::new_v4());
        cache.insert(key(1), v1);
        cache.insert(key(2), v2.clone());
        assert_eq!(cache.get(&key(1)), None, "capacity=1 evicted");
        assert_eq!(cache.get(&key(2)), Some(v2));
    }

    #[test]
    fn system_clock_returns_a_recent_time() {
        // Lightweight smoke for the production clock — `now()` is
        // within 60s of `Utc::now()`. Coverage tooling otherwise
        // marks `SystemClock::now` as untested.
        let clock = SystemClock;
        let t = clock.now();
        let delta = Utc::now().signed_duration_since(t).num_seconds().abs();
        assert!(delta < 60, "SystemClock returns near-now");
    }

    #[test]
    fn cache_capacity_eviction_cleans_reverse_index() {
        // capacity=1 — inserting key(2) must capacity-evict key(1)
        // AND remove its token_id from the reverse index. If the
        // reverse index leaked the evicted token_id, a subsequent
        // `invalidate_token(stale_id)` would silently `pop` the
        // currently-live entry under key(2). This pins that
        // off-by-one.
        let clock = MockClock::new(t0());
        let cache = cache_with_clock(1, Duration::from_secs(300), clock);
        let stale_id = Uuid::new_v4();
        let live_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        cache.insert(key(1), validation(stale_id, user_id));
        let v2 = validation(live_id, user_id);
        cache.insert(key(2), v2.clone());

        // Stale entry's token_id no longer maps anywhere — invalidating
        // it must NOT touch key(2).
        cache.invalidate_token(stale_id);

        assert_eq!(cache.get(&key(2)), Some(v2));
        let guard = cache.inner.lock().unwrap();
        assert!(!guard.reverse.contains_key(&stale_id));
        assert_eq!(guard.reverse.get(&live_id), Some(&key(2)));
    }
}
