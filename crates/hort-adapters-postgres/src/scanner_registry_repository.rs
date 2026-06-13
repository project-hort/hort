//! PostgreSQL implementation of [`ScannerRegistryRepository`] —
//! worker-coordination table from migration 009 (ADR 0009).
//!
//! The adapter uses the runtime `hort_app_role` Postgres role
//! (DML only — no DDL). Migration 009 grants `SELECT, INSERT,
//! UPDATE` on `scanner_registry` to that role.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::postgres::types::PgInterval;
use sqlx::{PgPool, Row};

use hort_domain::error::DomainResult;
use hort_domain::ports::scanner_registry_repository::{
    ScannerRegistryEntry, ScannerRegistryRepository,
};

use crate::{map_sqlx_error, BoxFuture};

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

    fn list_live<'a>(
        &'a self,
        liveness_window: Duration,
    ) -> BoxFuture<'a, DomainResult<Vec<ScannerRegistryEntry>>> {
        let interval = duration_to_pg_interval(liveness_window);
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT worker_id, backends, registered_at, last_heartbeat\n\
                   FROM public.scanner_registry\n\
                  WHERE last_heartbeat > now() - $1\n\
                  ORDER BY worker_id",
            )
            .bind(interval)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "ScannerRegistryEntry", "list_live"))?;

            rows.iter()
                .map(|row| {
                    let worker_id: String = row
                        .try_get("worker_id")
                        .map_err(|e| map_sqlx_error(&e, "ScannerRegistryEntry", "list_live"))?;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `duration_to_pg_interval` round-trips a typical 5-minute
    /// liveness window.
    #[test]
    fn duration_to_pg_interval_5_minutes() {
        let i = duration_to_pg_interval(Duration::from_secs(300));
        assert_eq!(i.months, 0);
        assert_eq!(i.days, 0);
        assert_eq!(i.microseconds, 300_000_000);
    }

    /// Overflow clamps rather than panics. Mirrors the jobs_repository
    /// adapter's helper.
    #[test]
    fn duration_to_pg_interval_clamps_overflow() {
        let i = duration_to_pg_interval(Duration::from_secs(u64::MAX / 2));
        assert_eq!(i.microseconds, i64::MAX);
    }

    /// Zero is zero microseconds — a degenerate liveness window
    /// returns an empty list (no rows match `> now() - 0`).
    #[test]
    fn duration_to_pg_interval_zero() {
        let i = duration_to_pg_interval(Duration::from_secs(0));
        assert_eq!(i.microseconds, 0);
    }
}
