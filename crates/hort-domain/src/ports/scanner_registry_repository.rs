//! Outbound port for the `scanner_registry` worker-coordination table
//! (migration 009).
//!
//! Each `hort-worker` calls
//! [`ScannerRegistryRepository::upsert_self`] on boot and refreshes
//! `last_heartbeat` every 60 seconds via
//! [`ScannerRegistryRepository::refresh_heartbeat`]. The apply-pipeline
//! consumes the read-side via [`ScannerRegistryRepository::list_live`]
//! to validate `ScanPolicy.scan_backends` entries against the union of
//! currently-registered backends.
//!
//! The table is mutable, not event-sourced — worker liveness does not
//! belong on the immutable event log.
//!
//! ```text
//! CREATE TABLE scanner_registry (
//!     worker_id      TEXT PRIMARY KEY,
//!     backends       TEXT[] NOT NULL,
//!     registered_at  TIMESTAMPTZ NOT NULL,
//!     last_heartbeat TIMESTAMPTZ NOT NULL
//! );
//! ```

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::DomainResult;

use super::BoxFuture;

/// One row in the `scanner_registry` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerRegistryEntry {
    /// Stable identifier the worker reports — pod name + random suffix
    /// in production (`HORT_WORKER_ID`).
    pub worker_id: String,
    /// Names of the [`crate::ports::scanner::ScannerPort`] backends this
    /// worker has wired (e.g. `["trivy", "osv"]`).
    pub backends: Vec<String>,
    /// Wall-clock time the worker first registered. Stable across
    /// heartbeat ticks; only `upsert_self` rewrites this column.
    pub registered_at: DateTime<Utc>,
    /// Wall-clock time of the most recent heartbeat — refreshed every
    /// 60 seconds by the worker. Operators treat a stale value
    /// (older than ~5 minutes) as "worker dead, investigate."
    pub last_heartbeat: DateTime<Utc>,
}

/// Outbound port for the `scanner_registry` table.
///
/// Only `hort-worker` writes rows (`upsert_self` on startup +
/// `refresh_heartbeat` on the 60s tick); `hort-server` reads via
/// `list_live` for apply-time policy validation. Both writers connect
/// via the `hort_app_role` Postgres role (DML-only, no DDL —
/// ADR 0009).
pub trait ScannerRegistryRepository: Send + Sync {
    /// Register this worker. Sets `registered_at = now()` if the row is
    /// new, leaves it unchanged otherwise. Always sets
    /// `last_heartbeat = now()` and rewrites `backends` so a worker
    /// that adds or drops a backend at restart immediately reflects the
    /// new list.
    fn upsert_self<'a>(
        &'a self,
        worker_id: &'a str,
        backends: Vec<String>,
    ) -> BoxFuture<'a, DomainResult<()>>;

    /// Update only `last_heartbeat` for `worker_id`. Called every 60s
    /// by the worker's heartbeat loop. A row that has not been
    /// `upsert_self`'d (operator-deleted, or worker never booted)
    /// surfaces as a no-op (the adapter's `UPDATE` matches zero rows
    /// silently — caller layer treats that as a logged warn).
    fn refresh_heartbeat<'a>(&'a self, worker_id: &'a str) -> BoxFuture<'a, DomainResult<()>>;

    /// List every row whose `last_heartbeat` is within the supplied
    /// liveness window — i.e. workers that have ticked recently
    /// enough to be considered alive. Used by apply-time policy
    /// validation and the operator-facing health
    /// endpoint.
    fn list_live<'a>(
        &'a self,
        liveness_window: Duration,
    ) -> BoxFuture<'a, DomainResult<Vec<ScannerRegistryEntry>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `ScannerRegistryRepository` is
    /// dyn-compatible — adapters store the trait object behind
    /// `Arc<dyn ScannerRegistryRepository>` in the worker
    /// composition root.
    #[test]
    fn scanner_registry_repository_is_dyn_compatible() {
        let _ = size_of::<&dyn ScannerRegistryRepository>();
    }

    /// `Box<dyn ScannerRegistryRepository>` resolves — proves the
    /// trait can be type-erased into an owned trait object.
    #[test]
    fn scanner_registry_repository_can_be_boxed() {
        let _: Option<Box<dyn ScannerRegistryRepository>> = None;
    }

    /// `ScannerRegistryEntry` is `Clone + PartialEq` so test fixtures
    /// can be cloned across mock interactions and assertions can use
    /// `assert_eq!`.
    #[test]
    fn scanner_registry_entry_is_clone_and_partial_eq() {
        let now = DateTime::<Utc>::from_timestamp(0, 0).expect("ts");
        let entry = ScannerRegistryEntry {
            worker_id: "worker-a".into(),
            backends: vec!["trivy".into(), "osv".into()],
            registered_at: now,
            last_heartbeat: now,
        };
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }
}
