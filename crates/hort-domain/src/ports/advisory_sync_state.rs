//! Outbound port for the `advisory_sync_state` checkpoint table.
//!
//! `AdvisoryWatchTickHandler` reads `last_sync_at` for each configured
//! feed (only `'osv'` in v1) at the start of every tick, calls
//! [`AdvisoryPort::pull_diff_since`](crate::ports::advisory::AdvisoryPort::pull_diff_since),
//! and — only when every ecosystem succeeded — writes back the new
//! checkpoint via [`AdvisorySyncStateRepository::set_last_sync_at`].
//! Partial-ecosystem failure leaves the timestamp untouched so the
//! next tick re-attempts the missed window.
//!
//! The `feed` argument is the `advisory_sync_state.feed` PRIMARY KEY
//! literal — `"osv"` in v1; future feeds (GitHub Advisory) add their
//! own row without a schema change.

use chrono::{DateTime, Utc};

use crate::error::DomainResult;

use super::BoxFuture;

/// Outbound port for the per-feed advisory-sync checkpoint.
pub trait AdvisorySyncStateRepository: Send + Sync {
    /// Return the `last_sync_at` value for `feed`, or `None` if no
    /// row exists for that feed.
    ///
    /// The migration seeds `('osv', now() - 24h)` at install time, so
    /// in production the v1 caller (`AdvisoryWatchTickHandler`) always
    /// sees `Some(_)` for the OSV feed. The handler still defaults to
    /// `now() - 24h` on `None` defensively — a fresh test database or
    /// a manually-truncated row should not crash the watch tick.
    fn get_last_sync_at<'a>(
        &'a self,
        feed: &'a str,
    ) -> BoxFuture<'a, DomainResult<Option<DateTime<Utc>>>>;

    /// Update `last_sync_at` for `feed` to `t`. Inserts the row if it
    /// does not exist (UPSERT semantics) so a checkpoint write against
    /// a feed whose seed was deleted recovers cleanly. `updated_at`
    /// is set to `now()` by the adapter.
    fn set_last_sync_at<'a>(
        &'a self,
        feed: &'a str,
        t: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DomainError;

    /// Compile-time assertion that `AdvisorySyncStateRepository` is
    /// dyn-compatible. Mirrors the same probe in
    /// `SbomComponentRepository`.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn AdvisorySyncStateRepository>();
    }

    /// `Box<dyn AdvisorySyncStateRepository>` resolves — proves the
    /// trait can be type-erased into an owned trait object the way
    /// adapter composition roots will store it.
    #[test]
    fn port_can_be_boxed() {
        let _: Option<Box<dyn AdvisorySyncStateRepository>> = None;
    }

    /// Minimal in-memory impl exercises both methods through the trait
    /// object — pins the dispatch shape the handler relies on.
    struct InMemorySyncState {
        last: std::sync::Mutex<Option<DateTime<Utc>>>,
    }

    impl InMemorySyncState {
        fn new(initial: Option<DateTime<Utc>>) -> Self {
            Self {
                last: std::sync::Mutex::new(initial),
            }
        }
    }

    impl AdvisorySyncStateRepository for InMemorySyncState {
        fn get_last_sync_at<'a>(
            &'a self,
            _feed: &'a str,
        ) -> BoxFuture<'a, DomainResult<Option<DateTime<Utc>>>> {
            let v = *self.last.lock().unwrap();
            Box::pin(async move { Ok(v) })
        }

        fn set_last_sync_at<'a>(
            &'a self,
            _feed: &'a str,
            t: DateTime<Utc>,
        ) -> BoxFuture<'a, DomainResult<()>> {
            *self.last.lock().unwrap() = Some(t);
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn round_trip_through_trait_object() {
        let initial = DateTime::<Utc>::from_timestamp(1_000_000, 0).unwrap();
        let repo: Box<dyn AdvisorySyncStateRepository> =
            Box::new(InMemorySyncState::new(Some(initial)));
        let got = repo.get_last_sync_at("osv").await.expect("get returns Ok");
        assert_eq!(got, Some(initial));

        let updated = DateTime::<Utc>::from_timestamp(2_000_000, 0).unwrap();
        repo.set_last_sync_at("osv", updated)
            .await
            .expect("set returns Ok");
        let got = repo.get_last_sync_at("osv").await.expect("get returns Ok");
        assert_eq!(got, Some(updated));
    }

    #[tokio::test]
    async fn missing_feed_returns_none() {
        let repo: Box<dyn AdvisorySyncStateRepository> = Box::new(InMemorySyncState::new(None));
        let got = repo
            .get_last_sync_at("nonexistent")
            .await
            .expect("get returns Ok");
        assert!(got.is_none());
    }

    /// `DomainError::Invariant` round-trips through the trait return
    /// type. Mirrors the equivalent test in `SbomComponentRepository`.
    #[tokio::test]
    async fn err_round_trips_through_port_signature() {
        struct FailingRepo;
        impl AdvisorySyncStateRepository for FailingRepo {
            fn get_last_sync_at<'a>(
                &'a self,
                _feed: &'a str,
            ) -> BoxFuture<'a, DomainResult<Option<DateTime<Utc>>>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
            fn set_last_sync_at<'a>(
                &'a self,
                _feed: &'a str,
                _t: DateTime<Utc>,
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
        }
        let r = FailingRepo;
        let err = r.get_last_sync_at("osv").await.unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        let err = r.set_last_sync_at("osv", Utc::now()).await.unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }
}
