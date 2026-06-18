//! `ScannerWorkerQueryUseCase`.
//!
//! Admin-only read of the `scanner_registry` worker-coordination table —
//! the operator-facing "which workers are alive?" surface behind
//! `GET /api/v1/admin/workers` and `hort admin workers list`.
//!
//! This is the consuming reader for [`ScannerRegistryRepository::list_all`]
//! (ADR 0000 "Scanner-registry read side orphaned" open item — H20 removed
//! the apply-time consumer; this restores one). The "alive vs stale"
//! decision is a **presentation policy** applied here, not a storage filter:
//! the adapter returns every registered row and this use case stamps each
//! with `live` + `last_seen_secs_ago` so a dead/wedged worker stays visible
//! rather than silently vanishing from the listing.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use hort_domain::events::ApiActor;
use hort_domain::ports::scanner_registry_repository::ScannerRegistryRepository;

use crate::error::AppResult;
use crate::use_cases::CallerPrivileges;

/// One worker row projected for the admin listing.
///
/// Mirrors [`ScannerRegistryEntry`](hort_domain::ports::scanner_registry_repository::ScannerRegistryEntry)
/// plus the two derived liveness fields. Not a domain type — the use case
/// owns the liveness projection, so it lives here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerWorkerView {
    /// Stable worker identifier (`HORT_WORKER_ID`).
    pub worker_id: String,
    /// Scanner backends this worker advertises (e.g. `["trivy", "osv"]`).
    pub backends: Vec<String>,
    /// When the worker first registered.
    pub registered_at: DateTime<Utc>,
    /// Most recent heartbeat.
    pub last_heartbeat: DateTime<Utc>,
    /// `true` when `last_heartbeat` is within
    /// [`LIVENESS_THRESHOLD_SECS`](ScannerWorkerQueryUseCase::LIVENESS_THRESHOLD_SECS)
    /// of now — i.e. the worker is heartbeating and presumed healthy.
    pub live: bool,
    /// Seconds since the last heartbeat, clamped at `0` (a heartbeat in
    /// the future under clock skew reads as `0`, never negative).
    pub last_seen_secs_ago: i64,
}

/// Application use case for `GET /api/v1/admin/workers`.
pub struct ScannerWorkerQueryUseCase {
    registry: Arc<dyn ScannerRegistryRepository>,
}

impl ScannerWorkerQueryUseCase {
    /// A worker whose most recent heartbeat is older than this is reported
    /// `live = false`. Matches the operator convention documented on
    /// [`ScannerRegistryEntry::last_heartbeat`](hort_domain::ports::scanner_registry_repository::ScannerRegistryEntry)
    /// ("older than ~5 minutes → worker dead, investigate"). The worker
    /// heartbeats every 60 s, so 5 minutes tolerates four missed ticks.
    pub const LIVENESS_THRESHOLD_SECS: i64 = 300;

    /// Construct from the outbound port. The Postgres adapter provides the
    /// production impl; the inline test mock provides the unit-test impl.
    pub fn new(registry: Arc<dyn ScannerRegistryRepository>) -> Self {
        Self { registry }
    }

    /// List every registered scanner worker with derived liveness.
    ///
    /// Admin-only — non-admin callers are denied before the registry is
    /// read (defence-in-depth; the HTTP edge already gates via the
    /// `AdminPrincipal` extractor).
    #[tracing::instrument(skip(self, privileges))]
    pub async fn list(
        &self,
        actor: ApiActor,
        privileges: CallerPrivileges,
    ) -> AppResult<Vec<ScannerWorkerView>> {
        // Authz first — a denial never reaches the registry read.
        if let Err(e) = privileges.require_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                "scanner-worker list denied: not admin",
            );
            return Err(e);
        }

        let rows = self.registry.list_all().await?;
        let now = Utc::now();
        let workers: Vec<ScannerWorkerView> = rows
            .into_iter()
            .map(|e| {
                let age_secs = (now - e.last_heartbeat).num_seconds();
                ScannerWorkerView {
                    worker_id: e.worker_id,
                    backends: e.backends,
                    registered_at: e.registered_at,
                    last_heartbeat: e.last_heartbeat,
                    live: age_secs <= Self::LIVENESS_THRESHOLD_SECS,
                    last_seen_secs_ago: age_secs.max(0),
                }
            })
            .collect();

        // Routine admin read (no state change) → debug, per the
        // Observability rules. The denial above is the audited info-level
        // event.
        tracing::debug!(worker_count = workers.len(), "admin listed scanner workers");
        Ok(workers)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use chrono::Duration as ChronoDuration;
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::scanner_registry_repository::ScannerRegistryEntry;
    use hort_domain::ports::BoxFuture;

    use super::*;
    use crate::use_cases::test_support::{
        admin_privileges, api_actor, reviewer_privileges, unprivileged,
    };

    /// Inline mock — returns a seeded row set from `list_all` and records
    /// how many times it was called (so the denied path can assert the
    /// registry was never read). `fail` makes `list_all` error.
    struct MockRegistry {
        rows: Mutex<Vec<ScannerRegistryEntry>>,
        list_all_calls: AtomicUsize,
        fail: Mutex<Option<DomainError>>,
    }

    impl MockRegistry {
        fn new() -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
                list_all_calls: AtomicUsize::new(0),
                fail: Mutex::new(None),
            }
        }
        fn seed(&self, rows: Vec<ScannerRegistryEntry>) {
            *self.rows.lock().unwrap() = rows;
        }
        fn fail_next(&self, e: DomainError) {
            *self.fail.lock().unwrap() = Some(e);
        }
        fn list_all_call_count(&self) -> usize {
            self.list_all_calls.load(Ordering::SeqCst)
        }
    }

    impl ScannerRegistryRepository for MockRegistry {
        fn upsert_self<'a>(
            &'a self,
            _worker_id: &'a str,
            _backends: Vec<String>,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn refresh_heartbeat<'a>(&'a self, _worker_id: &'a str) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn list_all<'a>(&'a self) -> BoxFuture<'a, DomainResult<Vec<ScannerRegistryEntry>>> {
            self.list_all_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if let Some(e) = self.fail.lock().unwrap().take() {
                    return Err(e);
                }
                Ok(self.rows.lock().unwrap().clone())
            })
        }
        fn prune_stale<'a>(
            &'a self,
            _older_than: std::time::Duration,
        ) -> BoxFuture<'a, DomainResult<u64>> {
            Box::pin(async { Ok(0) })
        }
    }

    fn entry(worker_id: &str, last_heartbeat: DateTime<Utc>) -> ScannerRegistryEntry {
        ScannerRegistryEntry {
            worker_id: worker_id.into(),
            backends: vec!["trivy".into()],
            registered_at: last_heartbeat,
            last_heartbeat,
        }
    }

    #[tokio::test]
    async fn list_admin_empty_registry_returns_empty_vec() {
        let registry = Arc::new(MockRegistry::new());
        let uc = ScannerWorkerQueryUseCase::new(registry.clone());
        let out = uc
            .list(api_actor(), admin_privileges())
            .await
            .expect("admin happy path");
        assert!(out.is_empty());
        assert_eq!(
            registry.list_all_call_count(),
            1,
            "registry read exactly once"
        );
    }

    /// Liveness projection: a fresh heartbeat → `live`, a 1-hour-old one →
    /// stale, and a future-skewed one clamps `last_seen_secs_ago` to 0.
    /// Covers both arms of the threshold and the `.max(0)` clamp.
    #[tokio::test]
    async fn list_admin_projects_live_stale_and_clamped() {
        let now = Utc::now();
        let registry = Arc::new(MockRegistry::new());
        registry.seed(vec![
            entry("w-fresh", now - ChronoDuration::seconds(10)),
            entry("w-stale", now - ChronoDuration::seconds(3600)),
            entry("w-future", now + ChronoDuration::seconds(60)),
        ]);
        let uc = ScannerWorkerQueryUseCase::new(registry);

        let out = uc
            .list(api_actor(), admin_privileges())
            .await
            .expect("admin happy path");
        assert_eq!(out.len(), 3);

        let fresh = out.iter().find(|w| w.worker_id == "w-fresh").unwrap();
        assert!(fresh.live, "10s-old heartbeat must be live");
        assert!(fresh.last_seen_secs_ago >= 0);

        let stale = out.iter().find(|w| w.worker_id == "w-stale").unwrap();
        assert!(!stale.live, "1h-old heartbeat must be stale");
        assert!(stale.last_seen_secs_ago >= 3500, "age ~3600s");

        let future = out.iter().find(|w| w.worker_id == "w-future").unwrap();
        assert!(future.live, "future heartbeat is within threshold → live");
        assert_eq!(
            future.last_seen_secs_ago, 0,
            "future heartbeat clamps to 0, never negative"
        );
    }

    #[tokio::test]
    async fn list_reviewer_returns_forbidden_and_does_not_read_registry() {
        let registry = Arc::new(MockRegistry::new());
        let uc = ScannerWorkerQueryUseCase::new(registry.clone());
        let err = uc
            .list(api_actor(), reviewer_privileges())
            .await
            .expect_err("reviewer must be forbidden");
        assert!(
            matches!(
                err,
                crate::error::AppError::Domain(DomainError::Forbidden(_))
            ),
            "expected Forbidden, got {err:?}"
        );
        assert_eq!(
            registry.list_all_call_count(),
            0,
            "denied path must not read the registry"
        );
    }

    /// Fully unprivileged caller — pins the `is_reviewer = false` arm of
    /// `require_admin()` for branch coverage.
    #[tokio::test]
    async fn list_unprivileged_returns_forbidden() {
        let registry = Arc::new(MockRegistry::new());
        let uc = ScannerWorkerQueryUseCase::new(registry.clone());
        let err = uc
            .list(api_actor(), unprivileged())
            .await
            .expect_err("unprivileged must be forbidden");
        assert!(matches!(
            err,
            crate::error::AppError::Domain(DomainError::Forbidden(_))
        ));
        assert_eq!(registry.list_all_call_count(), 0);
    }

    #[tokio::test]
    async fn list_propagates_registry_error() {
        let registry = Arc::new(MockRegistry::new());
        registry.fail_next(DomainError::Invariant("registry unavailable".into()));
        let uc = ScannerWorkerQueryUseCase::new(registry);
        let err = uc
            .list(api_actor(), admin_privileges())
            .await
            .expect_err("registry error must propagate");
        assert!(matches!(
            err,
            crate::error::AppError::Domain(DomainError::Invariant(_))
        ));
    }
}
