//! PostgreSQL implementation of [`ScannerRegistryRepository`] —
//! worker-coordination table from migration 009 (ADR 0009).
//!
//! The adapter uses the runtime `hort_app_role` Postgres role
//! (DML only — no DDL). Migration 009 grants `SELECT, INSERT, UPDATE,
//! DELETE` on `scanner_registry` to that role (DELETE backs the
//! `prune_stale` housekeeping sweep).

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::postgres::types::PgInterval;
use sqlx::{PgPool, Row};

use hort_domain::error::DomainResult;
use hort_domain::ports::scanner_registry_repository::{
    ScannerRegistryEntry, ScannerRegistryRepository,
};

use crate::{map_sqlx_error, BoxFuture};

/// Defensive cap on `list_all` — the admin read returns at most this many
/// of the most-recently-seen workers. `prune_stale` keeps the table well
/// under it; the cap only bites if pruning lags badly, and even then the
/// live workers (highest `last_heartbeat`) always sort to the top, so it
/// only ever drops the oldest dead rows.
const LIST_CAP: i64 = 1000;

/// PostgreSQL adapter for [`ScannerRegistryRepository`].
pub struct PgScannerRegistryRepository {
    pool: PgPool,
}

impl PgScannerRegistryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Convert a `Duration` into a `PgInterval` for `now() - $::interval`
/// arithmetic. Mirrors the helper in `jobs_repository.rs`. Clamps to
/// `i64::MAX` microseconds (~292,000 years) rather than panicking on
/// overflow.
fn duration_to_pg_interval(d: Duration) -> PgInterval {
    let micros: i64 = d.as_micros().try_into().unwrap_or(i64::MAX);
    PgInterval {
        months: 0,
        days: 0,
        microseconds: micros,
    }
}

impl ScannerRegistryRepository for PgScannerRegistryRepository {
    fn upsert_self<'a>(
        &'a self,
        worker_id: &'a str,
        backends: Vec<String>,
    ) -> BoxFuture<'a, DomainResult<()>> {
        let worker_id = worker_id.to_string();
        Box::pin(async move {
            tracing::debug!(
                worker_id = %worker_id,
                backend_count = backends.len(),
                "scanner_registry upsert_self",
            );
            // ON CONFLICT (worker_id) DO UPDATE — registered_at stays
            // pinned to the row's original value when a prior row exists
            // (only the first insertion sets it). backends + last_heartbeat
            // are always rewritten so a worker that adds/drops backends
            // at restart is visible immediately.
            sqlx::query(
                "INSERT INTO public.scanner_registry\n\
                     (worker_id, backends, registered_at, last_heartbeat)\n\
                 VALUES ($1, $2, now(), now())\n\
                 ON CONFLICT (worker_id) DO UPDATE SET\n\
                     backends = EXCLUDED.backends,\n\
                     last_heartbeat = EXCLUDED.last_heartbeat",
            )
            .bind(&worker_id)
            .bind(&backends)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "ScannerRegistryEntry", &worker_id))?;
            Ok(())
        })
    }

    fn refresh_heartbeat<'a>(&'a self, worker_id: &'a str) -> BoxFuture<'a, DomainResult<()>> {
        let worker_id = worker_id.to_string();
        Box::pin(async move {
            tracing::trace!(worker_id = %worker_id, "scanner_registry heartbeat");
            sqlx::query(
                "UPDATE public.scanner_registry\n\
                    SET last_heartbeat = now()\n\
                  WHERE worker_id = $1",
            )
            .bind(&worker_id)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "ScannerRegistryEntry", &worker_id))?;
            Ok(())
        })
    }

    fn list_all<'a>(&'a self) -> BoxFuture<'a, DomainResult<Vec<ScannerRegistryEntry>>> {
        Box::pin(async move {
            // Most-recently-seen first + a defensive `LIMIT`: the read is
            // admin-facing and must stay bounded even if pruning lags. Live
            // workers (highest `last_heartbeat`) always sort to the top, so
            // the cap only ever drops the oldest dead rows.
            let rows = sqlx::query(
                "SELECT worker_id, backends, registered_at, last_heartbeat\n\
                   FROM public.scanner_registry\n\
                  ORDER BY last_heartbeat DESC\n\
                  LIMIT $1",
            )
            .bind(LIST_CAP)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "ScannerRegistryEntry", "list_all"))?;

            rows.iter()
                .map(|row| {
                    let worker_id: String = row
                        .try_get("worker_id")
                        .map_err(|e| map_sqlx_error(&e, "ScannerRegistryEntry", "list_all"))?;
                    let backends: Vec<String> = row
                        .try_get("backends")
                        .map_err(|e| map_sqlx_error(&e, "ScannerRegistryEntry", &worker_id))?;
                    let registered_at: DateTime<Utc> = row
                        .try_get("registered_at")
                        .map_err(|e| map_sqlx_error(&e, "ScannerRegistryEntry", &worker_id))?;
                    let last_heartbeat: DateTime<Utc> = row
                        .try_get("last_heartbeat")
                        .map_err(|e| map_sqlx_error(&e, "ScannerRegistryEntry", &worker_id))?;
                    Ok(ScannerRegistryEntry {
                        worker_id,
                        backends,
                        registered_at,
                        last_heartbeat,
                    })
                })
                .collect()
        })
    }

    fn prune_stale<'a>(&'a self, older_than: Duration) -> BoxFuture<'a, DomainResult<u64>> {
        let interval = duration_to_pg_interval(older_than);
        Box::pin(async move {
            let result = sqlx::query(
                "DELETE FROM public.scanner_registry\n\
                  WHERE last_heartbeat < now() - $1",
            )
            .bind(interval)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "ScannerRegistryEntry", "prune_stale"))?;
            Ok(result.rows_affected())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `duration_to_pg_interval` round-trips a typical 7-day prune horizon.
    #[test]
    fn duration_to_pg_interval_7_days() {
        let i = duration_to_pg_interval(Duration::from_secs(7 * 24 * 3600));
        assert_eq!(i.months, 0);
        assert_eq!(i.days, 0);
        assert_eq!(i.microseconds, 7 * 24 * 3600 * 1_000_000);
    }

    /// Overflow clamps rather than panics. Mirrors the jobs_repository
    /// adapter's helper.
    #[test]
    fn duration_to_pg_interval_clamps_overflow() {
        let i = duration_to_pg_interval(Duration::from_secs(u64::MAX / 2));
        assert_eq!(i.microseconds, i64::MAX);
    }
}
