//! Outbound port for the `scanner_registry` worker-coordination table
//! (migration 009).
//!
//! Each `hort-worker` calls
//! [`ScannerRegistryRepository::upsert_self`] on boot and refreshes
//! `last_heartbeat` every 60 seconds via
//! [`ScannerRegistryRepository::refresh_heartbeat`]. The `hort-server`
//! admin worker-list endpoint consumes the read-side via
//! [`ScannerRegistryRepository::list_all`] to surface every registered
//! worker with its liveness. (The apply pipeline no longer reads this
//! table — H20 moved `scanBackends` validation onto the compiled-in
//! `hort_app::scanning::KNOWN_SCAN_BACKENDS` set; the "alive vs stale"
//! liveness threshold is now a presentation policy applied by the
//! consuming use case, not a storage filter.)
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
/// `list_all` for the admin worker-list endpoint. Both writers connect
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

    /// List registered worker rows, most-recently-seen first.
    /// Returns the raw rows; deciding which are "alive" vs "stale"
    /// (the ~5-minute `last_heartbeat` threshold) is a presentation
    /// policy applied by the consuming use case
    /// (`ScannerWorkerQueryUseCase`), not a storage filter — so a dead
    /// worker stays visible in the admin worker-list with its
    /// last-heartbeat age rather than silently vanishing.
    ///
    /// Implementations MUST bound the result defensively (the read is
    /// admin-facing and must not return an unbounded set if pruning ever
    /// lags). The Postgres adapter caps at the N most-recently-seen rows
    /// (`ORDER BY last_heartbeat DESC LIMIT N`); live workers always sort
    /// to the top, so the cap only ever drops the oldest dead rows.
    /// [`prune_stale`](Self::prune_stale) keeps the table well under the
    /// cap, so it is a safety bound, not pagination.
    fn list_all<'a>(&'a self) -> BoxFuture<'a, DomainResult<Vec<ScannerRegistryEntry>>>;

    /// Delete every worker row whose `last_heartbeat` is older than
    /// `older_than` (i.e. `last_heartbeat < now() - older_than`), returning
    /// the number of rows removed. Housekeeping for the worker-coordination
    /// table: pod churn (rollouts, HPA scaling) leaves a row per retired
    /// `worker_id` that never heartbeats again, so without this the table
    /// grows without bound. Driven by the `scanner-registry-prune` worker
    /// task on a cron cadence. Idempotent (re-running deletes the same
    /// already-gone set → 0). A live worker is never deleted — it
    /// heartbeats every 60 s, so its `last_heartbeat` is always recent.
    fn prune_stale<'a>(&'a self, older_than: Duration) -> BoxFuture<'a, DomainResult<u64>>;
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
