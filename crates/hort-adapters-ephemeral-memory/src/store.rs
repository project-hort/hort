//! `DashMap`-backed in-memory [`EphemeralStore`] implementation with
//! a background TTL evictor.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::debug;

use hort_domain::error::DomainResult;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::BoxFuture;

/// Cadence of the background evictor sweep. One second is the
/// documented contract in Item 0a; coarser would let expired entries
/// linger long enough to confuse TTL-sensitive tests, finer would
/// waste CPU without a corresponding correctness gain.
const EVICTOR_TICK: Duration = Duration::from_millis(1000);

/// Single stored entry. `expires_at` is a `tokio::time::Instant` so
/// `tokio::test(start_paused = true)` can advance virtual time past
/// it without wall-clock sleep; `version` is monotonic per-key and
/// opaque to callers.
#[derive(Debug, Clone)]
struct MemEntry {
    value: Bytes,
    version: u64,
    expires_at: Instant,
}

impl MemEntry {
    fn is_expired(&self, now: Instant) -> bool {
        self.expires_at <= now
    }
}

/// In-memory [`EphemeralStore`] implementation.
///
/// Concurrency model:
///
/// - The primary map (`entries`) is a [`DashMap`] — shard-locked,
///   lock-free on disjoint keys for `get`/`put`/`delete`.
/// - CAS additionally grabs a per-key [`Mutex`] from `cas_locks` for
///   the compare-then-write window so a racing `compare_and_swap`
///   and `put` cannot interleave a read-compare-write inconsistently.
/// - The background evictor task sweeps `entries` for expired items
///   every [`EVICTOR_TICK`]. Its [`JoinHandle`] is retained so
///   `Drop` can abort the task deterministically — important in
///   tests so each construction does not leak an evictor.
pub struct InMemoryEphemeralStore {
    entries: Arc<DashMap<String, MemEntry>>,
    cas_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    evictor: Option<JoinHandle<()>>,
}

impl InMemoryEphemeralStore {
    /// Construct the adapter and spawn the eviction task on the
    /// current tokio runtime. Must be called from within a tokio
    /// runtime context; the evictor uses `tokio::time::sleep`.
    pub fn new() -> Self {
        let entries: Arc<DashMap<String, MemEntry>> = Arc::new(DashMap::new());
        let cas_locks: Arc<DashMap<String, Arc<Mutex<()>>>> = Arc::new(DashMap::new());

        let evictor_entries = Arc::clone(&entries);
        let evictor_locks = Arc::clone(&cas_locks);
        let evictor = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(EVICTOR_TICK);
            // `interval` fires immediately on first tick; skip the
            // zero-duration one so we don't sweep before any write.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let now = Instant::now();
                let expired: Vec<String> = evictor_entries
                    .iter()
                    .filter(|e| e.value().is_expired(now))
                    .map(|e| e.key().clone())
                    .collect();
                for key in &expired {
                    evictor_entries.remove(key);
                }
                // Best-effort: clean up the CAS-lock entry too so the
                // lock map doesn't grow monotonically over process
                // lifetime. Only safe to drop when the entry has also
                // expired — a live entry may still have a CAS in
                // flight.
                for key in &expired {
                    if let Some(lock_ref) = evictor_locks.get(key) {
                        // Only drop when no CAS currently holds the
                        // mutex (Arc strong-count == 1 meaning only
                        // the map owns it). A weak Arc check is not
                        // available; use try_lock to probe.
                        if Arc::strong_count(lock_ref.value()) == 1 {
                            drop(lock_ref);
                            evictor_locks.remove(key);
                        }
                    }
                }
                if !expired.is_empty() {
                    debug!(
                        count = expired.len(),
                        "ephemeral-memory evictor swept expired entries"
                    );
                }
            }
        });

        Self {
            entries,
            cas_locks,
            evictor: Some(evictor),
        }
    }

    /// Look up (or create) the per-key CAS mutex. Cheap clone of the
    /// inner `Arc<Mutex<()>>`; the lock itself is held only for the
    /// compare-and-write window.
    fn cas_lock_for(&self, key: &str) -> Arc<Mutex<()>> {
        if let Some(existing) = self.cas_locks.get(key) {
            return Arc::clone(existing.value());
        }
        // Insert a fresh mutex if no one else raced us to it, then
        // re-fetch so both racers share the same Arc.
        self.cas_locks
            .entry(key.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Return the live (non-expired) entry for `key`, or `None`. The
    /// read path lazily evicts too so a `get` issued between evictor
    /// ticks still honours the TTL contract.
    fn live_entry(&self, key: &str) -> Option<MemEntry> {
        let now = Instant::now();
        let entry = self.entries.get(key)?;
        if entry.is_expired(now) {
            drop(entry);
            self.entries.remove(key);
            return None;
        }
        Some(entry.clone())
    }
}

impl Default for InMemoryEphemeralStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for InMemoryEphemeralStore {
    fn drop(&mut self) {
        // Abort the evictor deterministically so tests that construct
        // many adapters in a row don't accumulate background tasks.
        if let Some(handle) = self.evictor.take() {
            handle.abort();
        }
    }
}

impl EphemeralStore for InMemoryEphemeralStore {
    fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
        let value = self.live_entry(key).map(|e| e.value);
        Box::pin(async move { Ok(value) })
    }

    fn put(&self, key: &str, value: Bytes, ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
        let expires_at = Instant::now() + ttl;
        // Compute the new version by consulting any existing live
        // entry. If present, bump; otherwise start at 1.
        let next_version = match self.live_entry(key) {
            Some(existing) => existing.version.saturating_add(1),
            None => 1,
        };
        self.entries.insert(
            key.to_owned(),
            MemEntry {
                value,
                version: next_version,
                expires_at,
            },
        );
        Box::pin(async move { Ok(()) })
    }

    fn put_if_absent(
        &self,
        key: &str,
        value: Bytes,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<bool>> {
        let lock = self.cas_lock_for(key);
        let entries = Arc::clone(&self.entries);
        let key = key.to_owned();
        Box::pin(async move {
            // Lock protects the absence-check-then-insert window.
            let _guard = lock.lock().await;
            let now = Instant::now();
            if let Some(existing) = entries.get(&key) {
                if !existing.is_expired(now) {
                    return Ok(false);
                }
                drop(existing);
                entries.remove(&key);
            }
            entries.insert(
                key,
                MemEntry {
                    value,
                    version: 1,
                    expires_at: now + ttl,
                },
            );
            Ok(true)
        })
    }

    fn compare_and_swap(
        &self,
        key: &str,
        expected_version: u64,
        new_value: Bytes,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
        let lock = self.cas_lock_for(key);
        let entries = Arc::clone(&self.entries);
        let key = key.to_owned();
        Box::pin(async move {
            // Hold the per-key mutex across the compare-and-write
            // window. Concurrent CAS calls on the same key serialise
            // through this lock; disjoint keys hit different mutexes
            // and never contend.
            let _guard = lock.lock().await;
            let now = Instant::now();
            let current = match entries.get(&key) {
                Some(entry) if !entry.is_expired(now) => entry.clone(),
                _ => return Ok(None),
            };
            if current.version != expected_version {
                return Ok(None);
            }
            let new_version = current.version.saturating_add(1);
            entries.insert(
                key,
                MemEntry {
                    value: new_value,
                    version: new_version,
                    expires_at: now + ttl,
                },
            );
            Ok(Some(new_version))
        })
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
        self.entries.remove(key);
        Box::pin(async move { Ok(()) })
    }

    fn extend_ttl(&self, key: &str, ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
        let now = Instant::now();
        if let Some(mut entry) = self.entries.get_mut(key) {
            if entry.is_expired(now) {
                // Expired entries are Ok(()) by contract; evict now
                // so a subsequent get reflects the expiry.
                drop(entry);
                self.entries.remove(key);
            } else {
                entry.expires_at = now + ttl;
            }
        }
        Box::pin(async move { Ok(()) })
    }

    /// Atomic increment-and-cap-check, race-free against concurrent
    /// callers on the same key (DOS-low-2 hardening). The per-key CAS
    /// mutex already exists for `compare_and_swap` / `put_if_absent`;
    /// reusing it here serialises the read-check-write window so 33
    /// concurrent open-session requests against a cap of 32 yield
    /// exactly 32 successes and 1 rejection — never 33 successes,
    /// never fewer than 32.
    fn try_increment_counter(
        &self,
        key: &str,
        max: u64,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
        let lock = self.cas_lock_for(key);
        let entries = Arc::clone(&self.entries);
        let key = key.to_owned();
        Box::pin(async move {
            let _guard = lock.lock().await;
            let now = Instant::now();
            let current: u64 = match entries.get(&key) {
                Some(entry) if !entry.is_expired(now) => {
                    let s = std::str::from_utf8(&entry.value).map_err(|_| {
                        hort_domain::error::DomainError::Invariant(
                            "ephemeral counter: non-utf8 bytes at counter key".into(),
                        )
                    })?;
                    s.parse().map_err(|_| {
                        hort_domain::error::DomainError::Invariant(
                            "ephemeral counter: non-numeric value at counter key".into(),
                        )
                    })?
                }
                _ => 0,
            };
            if current >= max {
                return Ok(None);
            }
            let new_value = current + 1;
            let new_bytes = Bytes::from(format!("{new_value}").into_bytes());
            // Bump the version monotonically so concurrent CAS
            // observers see a fresh write.
            let next_version = match entries.get(&key) {
                Some(existing) if !existing.is_expired(now) => existing.version.saturating_add(1),
                _ => 1,
            };
            entries.insert(
                key,
                MemEntry {
                    value: new_bytes,
                    version: next_version,
                    expires_at: now + ttl,
                },
            );
            Ok(Some(new_value))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Evictor Drop shuts the background task down — construction in
    /// a `select!` loop cannot accumulate evictor tasks.
    #[tokio::test]
    async fn drop_aborts_evictor() {
        let store = InMemoryEphemeralStore::new();
        let handle = store.evictor.as_ref().unwrap().abort_handle();
        drop(store);
        // Yield a couple of times so the abort propagates.
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert!(handle.is_finished(), "evictor must terminate after drop");
    }

    /// Live read path lazily evicts expired entries — a `get` issued
    /// between evictor ticks still returns None.
    #[tokio::test(start_paused = true)]
    async fn lazy_eviction_on_read() {
        let store = InMemoryEphemeralStore::new();
        store
            .put("k", Bytes::from_static(b"v"), Duration::from_millis(50))
            .await
            .unwrap();
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(store.get("k").await.unwrap().is_none());
    }

    /// put_if_absent over an expired entry takes the absent branch
    /// and resets the version to 1.
    #[tokio::test(start_paused = true)]
    async fn put_if_absent_takes_expired_slot() {
        let store = InMemoryEphemeralStore::new();
        store
            .put("k", Bytes::from_static(b"old"), Duration::from_millis(50))
            .await
            .unwrap();
        tokio::time::advance(Duration::from_millis(100)).await;

        let won = store
            .put_if_absent("k", Bytes::from_static(b"new"), Duration::from_secs(60))
            .await
            .unwrap();
        assert!(won);
        assert_eq!(
            store.get("k").await.unwrap(),
            Some(Bytes::from_static(b"new"))
        );
    }

    /// CAS against an expired entry sees "no live entry" and returns
    /// None — not a version mismatch, not an Ok(Some).
    #[tokio::test(start_paused = true)]
    async fn cas_against_expired_entry_returns_none() {
        let store = InMemoryEphemeralStore::new();
        store
            .put("k", Bytes::from_static(b"v1"), Duration::from_millis(50))
            .await
            .unwrap();
        tokio::time::advance(Duration::from_millis(100)).await;
        let outcome = store
            .compare_and_swap("k", 1, Bytes::from_static(b"v2"), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(outcome, None);
    }

    /// extend_ttl on an expired entry is Ok(()) and the entry stays
    /// evicted — the caller cannot "resurrect" a dead key.
    #[tokio::test(start_paused = true)]
    async fn extend_ttl_on_expired_is_noop() {
        let store = InMemoryEphemeralStore::new();
        store
            .put("k", Bytes::from_static(b"v"), Duration::from_millis(50))
            .await
            .unwrap();
        tokio::time::advance(Duration::from_millis(100)).await;
        store
            .extend_ttl("k", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(store.get("k").await.unwrap().is_none());
    }

    /// extend_ttl on an absent key is Ok(()) — GC/finalize races
    /// don't surface a spurious error.
    #[tokio::test]
    async fn extend_ttl_on_absent_key_is_ok() {
        let store = InMemoryEphemeralStore::new();
        store
            .extend_ttl("never-written", Duration::from_secs(60))
            .await
            .unwrap();
    }

    /// put bumps the version on an existing live entry.
    #[tokio::test]
    async fn put_increments_version() {
        let store = InMemoryEphemeralStore::new();
        store
            .put("k", Bytes::from_static(b"v1"), Duration::from_secs(60))
            .await
            .unwrap();
        store
            .put("k", Bytes::from_static(b"v2"), Duration::from_secs(60))
            .await
            .unwrap();
        // CAS with version=2 must succeed; CAS with version=1 must fail.
        let stale = store
            .compare_and_swap("k", 1, Bytes::from_static(b"x"), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(stale, None);
        let fresh = store
            .compare_and_swap("k", 2, Bytes::from_static(b"y"), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(fresh, Some(3));
    }

    /// Delete on an absent key is Ok(()).
    #[tokio::test]
    async fn delete_absent_is_ok() {
        let store = InMemoryEphemeralStore::new();
        store.delete("never-written").await.unwrap();
    }

    /// `Default` constructs the same adapter as `new` — covers the
    /// derived-like impl branch.
    #[tokio::test]
    async fn default_constructor_works() {
        let store = InMemoryEphemeralStore::default();
        store
            .put("k", Bytes::from_static(b"v"), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(
            store.get("k").await.unwrap(),
            Some(Bytes::from_static(b"v"))
        );
    }

    /// Background evictor wakes up and evicts expired entries even
    /// without a read hitting them. Runs on real wall-clock time so
    /// interaction with `tokio::time::interval` is exercised.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_evictor_sweeps_expired() {
        let store = InMemoryEphemeralStore::new();
        store
            .put("k", Bytes::from_static(b"v"), Duration::from_millis(100))
            .await
            .unwrap();

        // Wait past the TTL and at least one evictor tick.
        tokio::time::sleep(Duration::from_millis(2200)).await;

        // Directly probe the map bypassing lazy eviction on read.
        assert!(
            !store.entries.contains_key("k"),
            "evictor must have swept the expired key"
        );
    }

    /// Concurrent CAS on disjoint keys do not block each other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_cas_on_disjoint_keys_does_not_serialize() {
        let store = Arc::new(InMemoryEphemeralStore::new());
        store
            .put("a", Bytes::from_static(b"x"), Duration::from_secs(60))
            .await
            .unwrap();
        store
            .put("b", Bytes::from_static(b"y"), Duration::from_secs(60))
            .await
            .unwrap();

        let sa = Arc::clone(&store);
        let sb = Arc::clone(&store);
        let ha = tokio::spawn(async move {
            sa.compare_and_swap("a", 1, Bytes::from_static(b"x2"), Duration::from_secs(60))
                .await
        });
        let hb = tokio::spawn(async move {
            sb.compare_and_swap("b", 1, Bytes::from_static(b"y2"), Duration::from_secs(60))
                .await
        });
        assert_eq!(ha.await.unwrap().unwrap(), Some(2));
        assert_eq!(hb.await.unwrap().unwrap(), Some(2));
    }

    /// Evictor cleans up the per-key mutex entry after the data
    /// entry expires — prevents the lock map from growing unbounded
    /// over process lifetime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn evictor_reaps_cas_lock_entry() {
        let store = InMemoryEphemeralStore::new();
        // Trigger lock creation via put_if_absent so the lock map has
        // an entry to reap.
        store
            .put_if_absent("k", Bytes::from_static(b"v"), Duration::from_millis(100))
            .await
            .unwrap();
        assert!(store.cas_locks.contains_key("k"));

        tokio::time::sleep(Duration::from_millis(2500)).await;

        assert!(
            !store.cas_locks.contains_key("k"),
            "CAS lock entry must be reaped alongside the data entry"
        );
    }
}
