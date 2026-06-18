//! PostgreSQL adapter for [`AdvisorySyncStateRepository`].
//!
//! Single-row-per-feed table. The migration seeds `('osv', now() - 24h)`
//! at install time, so the v1 caller (`AdvisoryWatchTickHandler`)
//! always sees a non-`None` checkpoint for the OSV feed in production.
//! The handler's `None` branch is defensive (fresh test database,
//! manually-truncated row) and resolves to a `now() - 24h` cold-start
//! window.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use hort_domain::error::DomainResult;
use hort_domain::ports::advisory_sync_state::AdvisorySyncStateRepository;

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL adapter for [`AdvisorySyncStateRepository`].
pub struct PgAdvisorySyncStateRepository {
    pool: PgPool,
}

impl PgAdvisorySyncStateRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl AdvisorySyncStateRepository for PgAdvisorySyncStateRepository {
    fn get_last_sync_at<'a>(
        &'a self,
        feed: &'a str,
    ) -> BoxFuture<'a, DomainResult<Option<DateTime<Utc>>>> {
        Box::pin(async move {
            let row: Option<(DateTime<Utc>,)> =
                sqlx::query_as("SELECT last_sync_at FROM advisory_sync_state WHERE feed = $1")
                    .bind(feed)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| map_sqlx_error(&e, "advisory_sync_state", feed))?;
            Ok(row.map(|(t,)| t))
        })
    }

    fn set_last_sync_at<'a>(
        &'a self,
        feed: &'a str,
        t: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            // UPSERT — first set on a feed without a seed row inserts;
            // subsequent updates overwrite both `last_sync_at` and
            // `updated_at`. `last_error` is preserved across UPSERTs
            // because v1 doesn't yet write it from the handler (the
            // table column exists for a future per-tick error
            // breadcrumb — see migration 010).
            sqlx::query(
                "INSERT INTO advisory_sync_state (feed, last_sync_at, updated_at) \
                 VALUES ($1, $2, now()) \
                 ON CONFLICT (feed) DO UPDATE \
                 SET last_sync_at = EXCLUDED.last_sync_at, \
                     updated_at = now()",
            )
            .bind(feed)
            .bind(t)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "advisory_sync_state", feed))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that the adapter implements the port.
    #[test]
    fn pg_adapter_implements_port() {
        fn assert_impl<T: AdvisorySyncStateRepository>() {}
        assert_impl::<PgAdvisorySyncStateRepository>();
    }
}
