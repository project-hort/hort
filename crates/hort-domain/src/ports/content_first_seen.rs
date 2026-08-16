//! Content-level age projection port — `first_seen_at`.
//!
//! Authority: `docs/adr/0054-content-level-age-evidence-anchors-quarantine.md`.
//!
//! Per SHA-256 content hash, hort holds the **minimum** over its own
//! ingest observations across every repository of the instance. That
//! minimum is the primary evidence source the quarantine window is
//! anchored on: unlike an upstream-asserted publish time, an
//! observation cannot be backdated, so it requires trusting nobody.
//!
//! # Why the fact is content-level, not per-row
//!
//! One CAS entry carries one `artifacts` row per repository that holds
//! it. An anchor living on that row differs between repositories for
//! identical bytes, and disappears when retention purges the row. This
//! projection is keyed by the content hash alone, is owned by no
//! repository, and is deleted by nothing — see the migration
//! (`migrations/019_content_first_seen.sql`) for the deliberate absence
//! of any foreign key.
//!
//! # Why `min` must be enforced by the adapter's SQL
//!
//! Concurrent ingests of the same content across different repositories
//! are the normal case. A read-modify-write in application code —
//! read the current value, compare, write the smaller — loses exactly
//! that race: two ingests both read "absent", both write their own
//! instant, and the later one wins. Implementations MUST therefore
//! compute the minimum inside a single statement against the locked
//! current row (the Postgres adapter uses `INSERT … ON CONFLICT DO
//! UPDATE … LEAST(…)`).
//!
//! Because the operation is a minimum, it is **order-insensitive and
//! idempotent**: observation order cannot change the stored value, and
//! re-observing an instant already covered is a no-op. That is what
//! makes the derived anchor race-independent by construction.
//!
//! # Write path
//!
//! Both artifact-minting paths in `IngestUseCase` record an
//! observation: the full ingest (which streams bytes into CAS) and the
//! by-hash registration (which mints a per-repo row over already-
//! resident CAS content). A coalesced follower observes the content
//! exactly as a leader does — that symmetry is the point of the ADR,
//! and it is why neither path may be the sole writer.
//!
//! # Read path
//!
//! [`ContentFirstSeenPort::first_seen`] is the read half. Anchor
//! derivation — combining this with the per-mapping trusted-upstream
//! second source and the future-skew clamp — is a separate unit of
//! work; today the projection is written and nothing derives an anchor
//! from it, so this port's presence changes no observable behaviour.

use chrono::{DateTime, Utc};

use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// Outbound port for the content-level `first_seen_at` projection.
pub trait ContentFirstSeenPort: Send + Sync {
    /// Record one ingest observation of `content_hash` at
    /// `observed_at`, keeping the **earlier** of the stored value and
    /// `observed_at`.
    ///
    /// Implementations MUST compute the minimum in the storage engine,
    /// atomically against the current row — never by reading the value
    /// into application code and writing back a comparison result.
    ///
    /// Idempotent and order-insensitive: calling this repeatedly, in
    /// any order, with any set of instants, converges on the smallest
    /// instant ever passed.
    fn observe(
        &self,
        content_hash: &ContentHash,
        observed_at: DateTime<Utc>,
    ) -> BoxFuture<'_, DomainResult<()>>;

    /// The earliest ingest observation recorded for `content_hash`, or
    /// `None` when this instance has never observed those bytes.
    ///
    /// `None` is not an error: content ingested before this projection
    /// existed has no record, and callers must treat the absence as
    /// "no first-seen evidence" rather than as an anomaly.
    fn first_seen(
        &self,
        content_hash: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Option<DateTime<Utc>>>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DomainError;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const HASH_B: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    fn hash(s: &str) -> ContentHash {
        s.parse().unwrap()
    }

    /// Compile-time assertion that the port is dyn-compatible — the
    /// composition root holds it as `Arc<dyn ContentFirstSeenPort>`.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn ContentFirstSeenPort>();
    }

    /// Minimal in-memory implementation used to pin the trait's
    /// documented semantics (min-keeping, idempotence, order
    /// insensitivity) at the port level, independent of any adapter.
    struct InMemoryFirstSeen {
        rows: Mutex<HashMap<String, DateTime<Utc>>>,
    }

    impl InMemoryFirstSeen {
        fn new() -> Self {
            Self {
                rows: Mutex::new(HashMap::new()),
            }
        }
    }

    impl ContentFirstSeenPort for InMemoryFirstSeen {
        fn observe(
            &self,
            content_hash: &ContentHash,
            observed_at: DateTime<Utc>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            let key = content_hash.as_ref().to_string();
            Box::pin(async move {
                let mut rows = self.rows.lock().unwrap();
                let slot = rows.entry(key).or_insert(observed_at);
                if observed_at < *slot {
                    *slot = observed_at;
                }
                Ok(())
            })
        }

        fn first_seen(
            &self,
            content_hash: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Option<DateTime<Utc>>>> {
            let key = content_hash.as_ref().to_string();
            Box::pin(async move { Ok(self.rows.lock().unwrap().get(&key).copied()) })
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    #[tokio::test]
    async fn first_seen_is_none_before_any_observation() {
        let port = InMemoryFirstSeen::new();
        assert_eq!(port.first_seen(&hash(HASH_A)).await.unwrap(), None);
    }

    /// The stored value is the minimum regardless of the order the
    /// observations arrive in — the property the derived anchor's
    /// race-independence rests on.
    #[tokio::test]
    async fn observations_keep_the_minimum_in_either_order() {
        let (early, late) = (at(1_000), at(2_000));

        let ascending = InMemoryFirstSeen::new();
        ascending.observe(&hash(HASH_A), early).await.unwrap();
        ascending.observe(&hash(HASH_A), late).await.unwrap();

        let descending = InMemoryFirstSeen::new();
        descending.observe(&hash(HASH_A), late).await.unwrap();
        descending.observe(&hash(HASH_A), early).await.unwrap();

        assert_eq!(
            ascending.first_seen(&hash(HASH_A)).await.unwrap(),
            Some(early)
        );
        assert_eq!(
            descending.first_seen(&hash(HASH_A)).await.unwrap(),
            Some(early)
        );
    }

    /// Re-observing an instant already covered changes nothing.
    #[tokio::test]
    async fn repeated_observation_is_idempotent() {
        let port = InMemoryFirstSeen::new();
        for _ in 0..3 {
            port.observe(&hash(HASH_A), at(1_000)).await.unwrap();
        }
        assert_eq!(
            port.first_seen(&hash(HASH_A)).await.unwrap(),
            Some(at(1_000))
        );
    }

    /// Records are per content hash — one hash's observations never
    /// move another's.
    #[tokio::test]
    async fn records_are_keyed_per_content_hash() {
        let port = InMemoryFirstSeen::new();
        port.observe(&hash(HASH_A), at(1_000)).await.unwrap();
        port.observe(&hash(HASH_B), at(9_000)).await.unwrap();
        assert_eq!(
            port.first_seen(&hash(HASH_A)).await.unwrap(),
            Some(at(1_000))
        );
        assert_eq!(
            port.first_seen(&hash(HASH_B)).await.unwrap(),
            Some(at(9_000))
        );
    }

    /// `DomainError` round-trips through both return signatures — the
    /// adapter surfaces SQL failures this way.
    #[tokio::test]
    async fn errors_round_trip_through_port_signatures() {
        struct ErrPort;
        impl ContentFirstSeenPort for ErrPort {
            fn observe(
                &self,
                _content_hash: &ContentHash,
                _observed_at: DateTime<Utc>,
            ) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Invariant("observe failed".into())) })
            }
            fn first_seen(
                &self,
                _content_hash: &ContentHash,
            ) -> BoxFuture<'_, DomainResult<Option<DateTime<Utc>>>> {
                Box::pin(async { Err(DomainError::Invariant("read failed".into())) })
            }
        }
        let p = ErrPort;
        assert!(matches!(
            p.observe(&hash(HASH_A), at(1)).await.unwrap_err(),
            DomainError::Invariant(_)
        ));
        assert!(matches!(
            p.first_seen(&hash(HASH_A)).await.unwrap_err(),
            DomainError::Invariant(_)
        ));
    }
}
