//! 60-second heartbeat — refreshes `scanner_registry.last_heartbeat`
//! and emits the `hort_scan_queue_depth` gauge (see `docs/metrics-catalog.md`).
//!
//! The first tick fires immediately so a freshly-booted worker
//! refreshes its heartbeat as soon as the loop spins up; thereafter
//! the loop sleeps 60 seconds between iterations. Shutdown is
//! observed via a watch channel; the loop returns on the first true
//! value.

use std::sync::Arc;
use std::time::Duration;

use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::scanner_registry_repository::ScannerRegistryRepository;

use crate::composition::WorkerContext;

/// Interval between heartbeat ticks. The 60-second cadence matches the
/// 5-minute liveness window configured in the Helm chart.
/// `hort_scan_queue_depth` is the gauge consumers' single source of truth
/// for "how many `pending` scan jobs are queued"; alerts and dashboards
/// bin on the 60s resolution. Both the heartbeat refresh and the gauge
/// read happen in the same `tick_once` body so the two signals stay
/// phase-locked.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// Run the heartbeat loop until shutdown is signalled.
///
/// The heartbeat owns BOTH the initial `scanner_registry.upsert_self`
/// (first tick) AND every subsequent `refresh_heartbeat`. The composition
/// root used to write the row itself before spawning this loop, leaving a
/// window in which a panic between the two left a stale registry row whose
/// `last_heartbeat` would never tick. Folding upsert into the loop's first
/// iteration eliminates that window: the row only ever exists when the
/// heartbeat task is also alive.
pub async fn run(ctx: Arc<WorkerContext>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    // `interval`'s first tick fires immediately — that's what we
    // want: refresh on boot rather than wait the full minute.
    let mut first_tick = true;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("hort-worker: heartbeat loop exiting on shutdown");
                    return;
                }
            }
            _ = interval.tick() => {
                tick_once(&ctx, first_tick).await;
                first_tick = false;
            }
        }
    }
}

/// Single heartbeat tick — exposed for tests that want to drive the
/// behaviour deterministically. `first_tick` is `true` exactly once
/// per loop, on boot: in that case the tick does an `upsert_self`
/// (registering the worker + its backends) instead of a plain
/// `refresh_heartbeat`. Subsequent ticks refresh only.
pub(crate) async fn tick_once(ctx: &WorkerContext, first_tick: bool) {
    refresh_registry(
        ctx.scanner_registry.as_ref(),
        &ctx.worker_id,
        &ctx.scanners,
        first_tick,
    )
    .await;

    // `hort_scan_queue_depth` gauge. Cadence is pinned at the same 60s
    // as the heartbeat refresh (see `HEARTBEAT_INTERVAL` above) so the
    // two signals stay phase-locked. Read goes through the
    // `JobsRepository` port — the previous direct-pool `SELECT count(*)`
    // bypassed the port boundary and forced the worker to know the SQL
    // shape. The port now owns the query.
    emit_queue_depth(ctx.jobs.as_ref()).await;
}

/// Touch the scanner-registry row through the port boundary.
///
/// On `first_tick == true`, fold a full `upsert_self` (registering
/// the worker + its backends) — M14 review finding: composition
/// root no longer writes the row itself, the heartbeat owns the
/// row's entire lifecycle so the registry write and the heartbeat's
/// liveness are inseparable. On every subsequent tick this is a
/// `refresh_heartbeat` only.
///
/// Errors are logged and swallowed — the registry row is operator
/// telemetry; failing to write it must not crash the worker (or
/// stop it from claiming jobs through `JobsRepository`).
pub(crate) async fn refresh_registry(
    registry: &dyn ScannerRegistryRepository,
    worker_id: &str,
    scanners: &[String],
    first_tick: bool,
) {
    if first_tick {
        if let Err(e) = registry.upsert_self(worker_id, scanners.to_vec()).await {
            tracing::warn!(
                worker_id = %worker_id,
                error = %e,
                "scanner_registry.upsert_self failed on first heartbeat tick",
            );
        }
    } else if let Err(e) = registry.refresh_heartbeat(worker_id).await {
        tracing::warn!(
            worker_id = %worker_id,
            error = %e,
            "heartbeat refresh failed",
        );
    }
}

/// Read the queue depth via the [`JobsRepository`] port and emit the
/// `hort_scan_queue_depth` gauge. Extracted so unit tests can drive the
/// metric path through a mock repo without standing up a Postgres
/// pool.
pub(crate) async fn emit_queue_depth(jobs: &dyn JobsRepository) {
    match jobs.pending_scan_count().await {
        Ok(depth) => {
            metrics::gauge!("hort_scan_queue_depth").set(depth as f64);
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "hort_scan_queue_depth query failed; gauge stale this tick",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::jobs_repository::ScanJob;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ContentHash;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    /// Minimal `JobsRepository` mock that exercises only the
    /// `pending_scan_count` path — every other method is a no-op
    /// `Ok`. Carries an `AtomicUsize` so tests can assert the count
    /// is what was returned through the port boundary.
    #[derive(Default)]
    struct MockJobsRepo {
        count_calls: AtomicUsize,
        depth: i64,
        force_err: bool,
    }

    impl JobsRepository for MockJobsRepo {
        fn claim_scan_jobs<'a>(
            &'a self,
            _worker_id: &'a str,
            _batch_size: u32,
            _lock_duration: Duration,
        ) -> BoxFuture<'a, DomainResult<Vec<ScanJob>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn mark_completed<'a>(
            &'a self,
            _job_id: Uuid,
            _result_summary: serde_json::Value,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn reschedule<'a>(
            &'a self,
            _job_id: Uuid,
            _backoff: Duration,
            _last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn mark_failed<'a>(
            &'a self,
            _job_id: Uuid,
            _last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn enqueue_scan<'a>(
            &'a self,
            _artifact_id: Uuid,
            _repository_id: Uuid,
            _content_hash: &'a ContentHash,
            _format: &'a str,
            _priority: i16,
            _trigger_source: &'a str,
        ) -> BoxFuture<'a, DomainResult<Uuid>> {
            Box::pin(async { Ok(Uuid::nil()) })
        }
        fn pending_scan_count<'a>(&'a self) -> BoxFuture<'a, DomainResult<i64>> {
            self.count_calls.fetch_add(1, Ordering::SeqCst);
            let depth = self.depth;
            let force_err = self.force_err;
            Box::pin(async move {
                if force_err {
                    Err(DomainError::Invariant("synthetic".into()))
                } else {
                    Ok(depth)
                }
            })
        }
    }

    /// L12: `emit_queue_depth` reads the gauge value through the
    /// `JobsRepository` port (NOT a hardcoded SQL string against the
    /// pool). One call to the port per tick.
    #[tokio::test]
    async fn emit_queue_depth_routes_through_jobs_port() {
        let repo = MockJobsRepo {
            depth: 42,
            ..Default::default()
        };
        emit_queue_depth(&repo).await;
        assert_eq!(
            repo.count_calls.load(Ordering::SeqCst),
            1,
            "the heartbeat tick must read the depth via the port exactly once"
        );
    }

    /// L12: errors from the port are swallowed (the gauge stays
    /// stale this tick) — the heartbeat loop must NOT propagate the
    /// failure or panic. Symmetrical with the prior direct-pool
    /// `tracing::warn!` behaviour.
    #[tokio::test]
    async fn emit_queue_depth_swallows_port_errors() {
        let repo = MockJobsRepo {
            force_err: true,
            ..Default::default()
        };
        // No panic, no `Result` propagated — the function returns
        // `()`. We only assert the call site is reachable; the
        // tracing emission is a side effect verified by code review
        // (no test infrastructure for `tracing::warn!` capture in
        // this crate).
        emit_queue_depth(&repo).await;
        assert_eq!(repo.count_calls.load(Ordering::SeqCst), 1);
    }

    // -----------------------------------------------------------------
    // M14: boot-order — heartbeat owns scanner_registry.upsert_self.
    // -----------------------------------------------------------------

    use hort_domain::ports::scanner_registry_repository::ScannerRegistryEntry;
    use std::sync::Mutex;

    /// Spy `ScannerRegistryRepository` that records every method
    /// invocation. M14 needs to assert WHO calls `upsert_self` and
    /// HOW often, so we instrument both write methods.
    #[derive(Default)]
    struct SpyRegistry {
        upsert_calls: Mutex<Vec<(String, Vec<String>)>>,
        refresh_calls: Mutex<Vec<String>>,
    }

    impl ScannerRegistryRepository for SpyRegistry {
        fn upsert_self<'a>(
            &'a self,
            worker_id: &'a str,
            backends: Vec<String>,
        ) -> BoxFuture<'a, DomainResult<()>> {
            self.upsert_calls
                .lock()
                .unwrap()
                .push((worker_id.to_string(), backends));
            Box::pin(async { Ok(()) })
        }
        fn refresh_heartbeat<'a>(&'a self, worker_id: &'a str) -> BoxFuture<'a, DomainResult<()>> {
            self.refresh_calls
                .lock()
                .unwrap()
                .push(worker_id.to_string());
            Box::pin(async { Ok(()) })
        }
        fn list_all<'a>(&'a self) -> BoxFuture<'a, DomainResult<Vec<ScannerRegistryEntry>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn prune_stale<'a>(&'a self, _older_than: Duration) -> BoxFuture<'a, DomainResult<u64>> {
            Box::pin(async { Ok(0) })
        }
    }

    /// M14: the heartbeat's first tick calls `upsert_self` (NOT
    /// `refresh_heartbeat`). This pins the contract that the
    /// registry row is written by the heartbeat task — the
    /// composition root no longer races a `refresh_heartbeat` that
    /// would silently no-op against a missing row.
    #[tokio::test]
    async fn first_tick_calls_upsert_self_not_refresh() {
        let registry = SpyRegistry::default();
        let backends = vec!["trivy".to_string(), "osv".to_string()];

        refresh_registry(&registry, "worker-7", &backends, true).await;

        let upserts = registry.upsert_calls.lock().unwrap();
        let refreshes = registry.refresh_calls.lock().unwrap();
        assert_eq!(
            upserts.len(),
            1,
            "first tick must call upsert_self exactly once"
        );
        assert_eq!(upserts[0].0, "worker-7");
        assert_eq!(upserts[0].1, backends);
        assert!(
            refreshes.is_empty(),
            "first tick must NOT call refresh_heartbeat (upsert covers it)"
        );
    }

    /// M14: subsequent ticks (`first_tick=false`) call
    /// `refresh_heartbeat` only — `upsert_self` is reserved for the
    /// initial registration so subsequent ticks do not rewrite
    /// `registered_at`.
    #[tokio::test]
    async fn subsequent_tick_calls_refresh_heartbeat_only() {
        let registry = SpyRegistry::default();
        let backends = vec!["trivy".to_string()];

        // Two non-first ticks.
        refresh_registry(&registry, "worker-7", &backends, false).await;
        refresh_registry(&registry, "worker-7", &backends, false).await;

        let upserts = registry.upsert_calls.lock().unwrap();
        let refreshes = registry.refresh_calls.lock().unwrap();
        assert!(
            upserts.is_empty(),
            "subsequent ticks must NOT call upsert_self"
        );
        assert_eq!(
            refreshes.len(),
            2,
            "two subsequent ticks must call refresh_heartbeat twice"
        );
        assert_eq!(refreshes[0], "worker-7");
        assert_eq!(refreshes[1], "worker-7");
    }

    /// M14: the heartbeat's first-tick `upsert_self` failure is
    /// logged and swallowed — same contract as the
    /// `refresh_heartbeat` failure path on subsequent ticks. A
    /// transient registry write failure must NOT crash the worker
    /// or block the queue-depth gauge emission downstream.
    #[tokio::test]
    async fn first_tick_swallows_upsert_errors() {
        struct FailingRegistry;
        impl ScannerRegistryRepository for FailingRegistry {
            fn upsert_self<'a>(
                &'a self,
                _worker_id: &'a str,
                _backends: Vec<String>,
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Invariant("registry unavailable".into())) })
            }
            fn refresh_heartbeat<'a>(
                &'a self,
                _worker_id: &'a str,
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn list_all<'a>(&'a self) -> BoxFuture<'a, DomainResult<Vec<ScannerRegistryEntry>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn prune_stale<'a>(
                &'a self,
                _older_than: Duration,
            ) -> BoxFuture<'a, DomainResult<u64>> {
                Box::pin(async { Ok(0) })
            }
        }
        // Returns `()` despite the error — no panic, no propagated
        // failure.
        refresh_registry(&FailingRegistry, "w", &[], true).await;
    }
}
