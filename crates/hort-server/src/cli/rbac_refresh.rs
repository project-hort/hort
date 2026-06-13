//! RBAC evaluator live-refresh background task.
//!
//! The task polls `PermissionGrantRepository::list_all` every
//! `HORT_RBAC_REFRESH_SECS` (default 30). If the snapshot differs from
//! the currently-held [`RbacEvaluator`], it replaces the pointer inside
//! `AuthContext::Enabled.rbac`'s [`ArcSwap`] atomically — readers on the
//! hot path pick up the new snapshot on their next `.load()` without any
//! lock contention.
//!
//! The additive-claims evaluator (ADR 0012) is built from a flat
//! `Vec<PermissionGrant>` (`RbacEvaluator::new(grants)`); there is no
//! role table or role-keyed grant index, so the refresh task does not
//! fetch roles — a single `list_all` grant query is the whole
//! snapshot.
//!
//! **Why polling, not LISTEN/NOTIFY?** Polling was chosen for
//! simplicity and bounded load. With a 30 s default and sub-10 k grants a
//! full snapshot fetch is trivially cheap. Thundering-herd across multiple
//! replicas is mitigated by the initial jitter delay (random ms in
//! `[0, 5000)` applied before the first fire).
//!
//! **Shutdown.** The task is wired into [`crate::shutdown::ShutdownHandle`]:
//! its tokio select arm on [`tokio_util::sync::CancellationToken::cancelled`]
//! breaks the sleep early and exits cleanly on SIGTERM/SIGINT.
//!
//! **Observability.**
//! - `hort_rbac_snapshot_reloads_total{result}` with values `success`
//!   (changed snapshot swapped in), `unchanged` (no diff), `failed`
//!   (DB query error — old snapshot retained).
//! - `tracing::info!` on success-with-change carries change counts
//!   (roles / grants added, removed) — never role or grant values
//!   (cardinality / PII-adjacency).
//! - `tracing::debug!` on unchanged polls.
//! - `tracing::warn!` on failures.
//!
//! **Signature tracking.** `RbacEvaluator`'s internal state is
//! deliberately private — the refresh task cannot reflect into it and
//! must not reach into `hort-app` internals. Instead,
//! the loop maintains its own `last_signature` (a set of
//! `(subject, repo_id_or_none, permission)` grant keys) alongside the
//! `ArcSwap` handle. Every poll compares the incoming signature against
//! the stored one; a mismatch triggers a swap + signature update. The
//! first-ever poll has no stored signature → either the incoming data
//! matches the `initial_signature` captured at composition time (built
//! from the same `grants` `build_app_context` used to seed the
//! evaluator) → `unchanged`, or the data has drifted since startup →
//! `success` with the full delta.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rand::Rng;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use hort_app::rbac::RbacEvaluator;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;

// ---------------------------------------------------------------------------
// Metric labels — catalog: `docs/metrics-catalog.md` §RBAC snapshot refresh.
// ---------------------------------------------------------------------------

const METRIC_NAME: &str = "hort_rbac_snapshot_reloads_total";
const RESULT_SUCCESS: &str = "success";
const RESULT_UNCHANGED: &str = "unchanged";
const RESULT_FAILED: &str = "failed";

/// Upper bound of the startup jitter window
/// ("rand::random::<u64>() % 5000 ms").
pub(crate) const JITTER_MAX_MS: u64 = 5_000;

// ---------------------------------------------------------------------------
// Signature — structural identity of an RBAC snapshot
// ---------------------------------------------------------------------------

/// Hashable, order-stable identity of a [`GrantSubject`].
///
/// `GrantSubject` is only `PartialEq` (its `Claims(Vec<String>)` arm
/// can't be `Eq + Hash` as-is). The signature needs set membership, so
/// the subject is normalised here: `Claims` is sorted + deduplicated so
/// `["a","b"]` and `["b","a","b"]` collapse to the same key (the
/// evaluator's subset match is order/multiplicity-insensitive), and
/// `User` carries the bare uuid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum GrantSubjectKey {
    Claims(Vec<String>),
    User(Uuid),
}

impl GrantSubjectKey {
    fn from_subject(subject: &GrantSubject) -> Self {
        match subject {
            GrantSubject::Claims(claims) => {
                let mut c: Vec<String> = claims.clone();
                c.sort();
                c.dedup();
                Self::Claims(c)
            }
            GrantSubject::User(uid) => Self::User(*uid),
        }
    }
}

/// Deterministic structural signature of a flat grant set (ADR 0012).
///
/// `grant_keys` — `(subject, repository_id_or_none, permission)`
/// triples. Grant id is intentionally NOT part of the key: re-seeding
/// an identical grant with a new uuid must register as unchanged
/// (operators replaying gitops config don't want a flood of `success`
/// reloads). There is no `role_ids` set and no
/// role table; the grant set is the whole structural identity.
///
/// Signatures over `PartialEq` are equivalent iff the evaluator would
/// return the same authorization decision for every call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Signature {
    grant_keys: HashSet<(GrantSubjectKey, Option<Uuid>, Permission)>,
}

impl Signature {
    /// Build a signature from the flat grant vector that
    /// `PermissionGrantRepository::list_all` returned. Cheap: one pass.
    pub(crate) fn from_grants(grants: &[PermissionGrant]) -> Self {
        let grant_keys: HashSet<(GrantSubjectKey, Option<Uuid>, Permission)> = grants
            .iter()
            .map(|g| {
                (
                    GrantSubjectKey::from_subject(&g.subject),
                    g.repository_id,
                    g.permission,
                )
            })
            .collect();
        Self { grant_keys }
    }

    /// Structural delta: how many grant keys were added or removed
    /// relative to `other`.
    pub(crate) fn diff(&self, other: &Signature) -> SnapshotDiff {
        let added_grants = self.grant_keys.difference(&other.grant_keys).count();
        let removed_grants = other.grant_keys.difference(&self.grant_keys).count();
        SnapshotDiff {
            added_grants,
            removed_grants,
        }
    }
}

/// Summary of the structural delta between two snapshots.
///
/// Counts only — never subject claim names or grant tuples (cardinality
/// control plus PII-adjacency; claim names may encode department
/// identifiers operators don't want in logs).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SnapshotDiff {
    pub added_grants: usize,
    pub removed_grants: usize,
}

impl SnapshotDiff {
    pub(crate) fn is_unchanged(&self) -> bool {
        self.added_grants == 0 && self.removed_grants == 0
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Spawn the RBAC refresh loop on the current Tokio runtime.
///
/// `initial_signature` must be the signature of the snapshot already
/// loaded into `rbac_handle` at composition time (i.e. built from the
/// same `grants` that seeded the `RbacEvaluator` in
/// `composition::build_app_context`). The first poll compares incoming
/// data against this signature — if the DB hasn't changed since startup,
/// the first poll registers as `unchanged` rather than (falsely)
/// `success`.
///
/// `interval` is a parameter (not `Config::rbac_refresh_secs` directly) so
/// tests can drive a much shorter cadence — a 30 s real refresh isn't
/// exercisable under `cargo test`.
///
/// Returns a [`tokio::task::JoinHandle`] so the serve path can `join!` it
/// alongside `axum::serve` and propagate panics. The task exits cleanly
/// when `shutdown` fires.
pub(crate) fn spawn(
    rbac_handle: Arc<ArcSwap<RbacEvaluator>>,
    grant_repo: Arc<dyn PermissionGrantRepository>,
    initial_signature: Signature,
    interval: Duration,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_loop(
            rbac_handle,
            grant_repo,
            initial_signature,
            interval,
            shutdown,
        )
        .await;
    })
}

// ---------------------------------------------------------------------------
// Core loop
// ---------------------------------------------------------------------------

async fn run_loop(
    rbac_handle: Arc<ArcSwap<RbacEvaluator>>,
    grant_repo: Arc<dyn PermissionGrantRepository>,
    initial_signature: Signature,
    interval: Duration,
    shutdown: CancellationToken,
) {
    let jitter = initial_jitter();
    tracing::info!(
        interval_secs = interval.as_secs(),
        jitter_ms = jitter.as_millis() as u64,
        "rbac refresh task starting"
    );

    // Initial jitter — split before the first poll so multiple replicas
    // don't hammer Postgres on the same edge. A shutdown during the
    // jitter window exits immediately; we do NOT fire a poll on the way
    // out.
    tokio::select! {
        _ = tokio::time::sleep(jitter) => {}
        _ = shutdown.cancelled() => {
            tracing::info!("rbac refresh task shutting down before first poll");
            return;
        }
    }

    let mut last_signature = initial_signature;
    loop {
        refresh_once(&rbac_handle, grant_repo.as_ref(), &mut last_signature).await;

        // Sleep until the next tick OR shutdown. `select!` arbitrates
        // fairly; a pending shutdown wins over a pending sleep.
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.cancelled() => {
                tracing::info!("rbac refresh task shutting down");
                return;
            }
        }
    }
}

/// Produce a random jitter duration in `[0, JITTER_MAX_MS)` ms.
///
/// Extracted so the "what window do we roll in" contract is pinned by
/// unit tests — the rest of the loop is harder to drive without a
/// runtime harness.
fn initial_jitter() -> Duration {
    let ms = rand::thread_rng().gen_range(0..JITTER_MAX_MS);
    Duration::from_millis(ms)
}

/// Run a single poll-compare-swap cycle.
///
/// `last_signature` is mutated in place on success so subsequent polls
/// detect changes relative to what was last swapped in. On `failed`
/// paths the signature is left untouched (old snapshot retained, so the
/// signature recording it must also be retained).
///
/// `pub(crate)` so tests can drive a single cycle deterministically —
/// no runtime harness needed.
pub(crate) async fn refresh_once(
    rbac_handle: &Arc<ArcSwap<RbacEvaluator>>,
    grant_repo: &dyn PermissionGrantRepository,
    last_signature: &mut Signature,
) {
    // Fetch the full snapshot: a single `list_all` grant
    // query is the whole snapshot (no role table). Retain-old-
    // snapshot-on-error contract — errors keep
    // the previous snapshot (stale-but-safe); we never fail open.
    let grants = match grant_repo.list_all().await {
        Ok(g) => g,
        Err(err) => {
            metrics::counter!(METRIC_NAME, "result" => RESULT_FAILED).increment(1);
            tracing::warn!(error = %err, "rbac snapshot refresh failed: list_all");
            return;
        }
    };

    let incoming = Signature::from_grants(&grants);
    let diff = incoming.diff(last_signature);

    if diff.is_unchanged() {
        metrics::counter!(METRIC_NAME, "result" => RESULT_UNCHANGED).increment(1);
        tracing::debug!("rbac snapshot unchanged");
        return;
    }

    // Build the new evaluator (consumes owned `grants`) and swap the
    // pointer atomically. `ArcSwap::store` is lock-free.
    let next = Arc::new(RbacEvaluator::new(grants));
    rbac_handle.store(next);
    *last_signature = incoming;
    metrics::counter!(METRIC_NAME, "result" => RESULT_SUCCESS).increment(1);
    tracing::info!(
        added_grants = diff.added_grants,
        removed_grants = diff.removed_grants,
        "rbac snapshot refreshed"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use chrono::Utc;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};

    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::PermissionGrant;
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::BoxFuture;

    // -- Mock grant repository --------------------------------------------

    /// In-memory [`PermissionGrantRepository`] double (there is no role
    /// table, so the refresh task drives `list_all` only). Tests install
    /// flat `PermissionGrant`s, then drive `refresh_once`
    /// deterministically. `fail` flips the next `list_all` to return
    /// `DomainError::Invariant` so the retain-old-snapshot path is
    /// testable.
    struct MockGrantRepo {
        grants: Mutex<Vec<PermissionGrant>>,
        fail: Mutex<bool>,
        list_calls: AtomicUsize,
    }

    impl MockGrantRepo {
        fn new() -> Self {
            Self {
                grants: Mutex::new(Vec::new()),
                fail: Mutex::new(false),
                list_calls: AtomicUsize::new(0),
            }
        }

        fn install_grant(&self, grant: PermissionGrant) {
            self.grants.lock().unwrap().push(grant);
        }

        fn set_fail(&self, fail: bool) {
            *self.fail.lock().unwrap() = fail;
        }

        fn list_calls(&self) -> usize {
            self.list_calls.load(Ordering::Relaxed)
        }
    }

    impl PermissionGrantRepository for MockGrantRepo {
        fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>> {
            self.list_calls.fetch_add(1, Ordering::Relaxed);
            let should_fail = *self.fail.lock().unwrap();
            let grants = self.grants.lock().unwrap().clone();
            Box::pin(async move {
                if should_fail {
                    Err(DomainError::Invariant("mock rbac refresh failure".into()))
                } else {
                    Ok(grants)
                }
            })
        }

        fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>> {
            // The refresh task never calls this — `list_all` is the
            // whole snapshot. Return an empty set so the double is a
            // complete trait impl.
            Box::pin(async { Ok(Vec::new()) })
        }

        fn save_managed(&self, _items: &[PermissionGrant]) -> BoxFuture<'_, DomainResult<()>> {
            // Not exercised by the refresh task (read-once-at-boot
            // contract — the apply pipeline owns the write path).
            Box::pin(async { Ok(()) })
        }
    }

    // -- Fixture builders -------------------------------------------------

    /// A global `developer`-claim grant carrying `Permission::Write`
    /// (flat `GrantSubject::Claims` grant, no role row — ADR 0012).
    fn dev_grant() -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["developer".into()]),
            repository_id: None,
            permission: Permission::Write,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    /// A global `reader`-claim grant carrying `Permission::Read`.
    fn reader_grant() -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["reader".into()]),
            repository_id: None,
            permission: Permission::Read,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    fn empty_handle() -> Arc<ArcSwap<RbacEvaluator>> {
        Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(Vec::new())))
    }

    // -- Metric capture helpers -------------------------------------------

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn find<'a>(
        entries: &'a [MetricEntry],
        kind: MetricKind,
        name: &str,
        expected: &[(&str, &str)],
    ) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != kind || ck.key().name() != name {
                return None;
            }
            let ok = expected
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            ok.then_some(dv)
        })
    }

    fn capture<F, Fut>(f: F) -> Snapshot
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f());
        });
        snapshotter.snapshot()
    }

    // =====================================================================
    // refresh_once — happy-path / failure / unchanged
    // =====================================================================

    #[test]
    fn refresh_once_swaps_evaluator_when_grant_added() {
        // Starting signature is empty (freshly-booted server with no
        // grants). The repo holds one developer grant. First poll
        // observes a new grant → swap → next request authorizes
        // correctly.
        let repo = Arc::new(MockGrantRepo::new());
        let handle = empty_handle();
        let handle_for_task = handle.clone();
        let mut sig = Signature::default();

        repo.install_grant(dev_grant());

        let snap = capture(|| {
            let repo = repo.clone();
            async move {
                refresh_once(&handle_for_task, repo.as_ref(), &mut sig).await;
            }
        });

        // Principal carrying the `developer` claim is now allowed to
        // Write — the swap must have committed, because the starting
        // evaluator was empty.
        let evaluator = handle.load_full();
        let principal = hort_domain::entities::caller::CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "s".into(),
            username: "u".into(),
            email: "e@x".into(),
            claims: vec!["developer".into()],
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        };
        assert!(evaluator.authorize(&principal, Permission::Write, None));

        // Metric fires with `result=success`.
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            METRIC_NAME,
            &[("result", RESULT_SUCCESS)],
        )
        .expect("success counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn refresh_once_retains_evaluator_on_db_failure() {
        // Seed the handle with a non-empty baseline, then make the repo
        // fail on the next call. The evaluator pointer must not change
        // AND the signature must not mutate.
        let repo = Arc::new(MockGrantRepo::new());
        let dev = dev_grant();
        let baseline_grants = vec![dev.clone()];
        let baseline = RbacEvaluator::new(baseline_grants.clone());
        let handle: Arc<ArcSwap<RbacEvaluator>> = Arc::new(ArcSwap::from_pointee(baseline));
        let handle_for_task = handle.clone();
        let baseline_ptr = Arc::as_ptr(&handle.load_full());
        let sig_before = Signature::from_grants(&baseline_grants);

        // Also install some different data in the repo so that if the
        // failure flag wasn't respected, the diff-and-swap path would
        // change the pointer. This makes the retention invariant robust
        // to an accidental skip of the failure guard.
        repo.install_grant(reader_grant());
        repo.set_fail(true);

        // Share the signature through a Mutex so we can inspect the
        // mutated value after the async call — the closure must own
        // `&mut sig` for the duration of the async block.
        let sig_cell: Arc<Mutex<Signature>> = Arc::new(Mutex::new(sig_before.clone()));
        let sig_for_task = sig_cell.clone();

        let snap = capture(|| {
            let repo = repo.clone();
            let sig_for_task = sig_for_task.clone();
            async move {
                let mut sig = sig_for_task.lock().unwrap().clone();
                refresh_once(&handle_for_task, repo.as_ref(), &mut sig).await;
                *sig_for_task.lock().unwrap() = sig;
            }
        });

        // Pointer unchanged — baseline retained.
        let current_ptr = Arc::as_ptr(&handle.load_full());
        assert_eq!(baseline_ptr, current_ptr);
        // Signature untouched on failure paths — so the next successful
        // poll computes deltas relative to what is actually loaded, not
        // what we wished had loaded.
        assert_eq!(*sig_cell.lock().unwrap(), sig_before);

        // Metric fires with `result=failed`.
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            METRIC_NAME,
            &[("result", RESULT_FAILED)],
        )
        .expect("failed counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn refresh_once_unchanged_emits_unchanged_metric_and_preserves_pointer() {
        // Seed handle + signature from the same grant set the repo will
        // return — a freshly-started server that hasn't had DB changes
        // between boot and first poll. First poll must fire
        // `result=unchanged` and must not swap the pointer.
        let repo = Arc::new(MockGrantRepo::new());
        let dev = dev_grant();
        repo.install_grant(dev.clone());

        let grants = vec![dev];
        let baseline = RbacEvaluator::new(grants.clone());
        let handle: Arc<ArcSwap<RbacEvaluator>> = Arc::new(ArcSwap::from_pointee(baseline));
        let baseline_ptr = Arc::as_ptr(&handle.load_full());
        let mut sig = Signature::from_grants(&grants);
        let handle_for_task = handle.clone();

        let snap = capture(|| {
            let repo = repo.clone();
            async move {
                refresh_once(&handle_for_task, repo.as_ref(), &mut sig).await;
            }
        });

        // Pointer unchanged — no swap fired.
        let after_ptr = Arc::as_ptr(&handle.load_full());
        assert_eq!(baseline_ptr, after_ptr);

        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            METRIC_NAME,
            &[("result", RESULT_UNCHANGED)],
        )
        .expect("unchanged counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
        // No `success` on this poll.
        assert!(find(
            &entries,
            MetricKind::Counter,
            METRIC_NAME,
            &[("result", RESULT_SUCCESS)]
        )
        .is_none());
    }

    #[test]
    fn refresh_once_swaps_when_only_grant_subject_claims_change() {
        // Subject-model regression: the same permission /
        // repository scope but a *different required-claim set* is a
        // structural change and must swap. Starting evaluator grants
        // `developer` Write; the repo now grants `reader` Write instead.
        let repo = Arc::new(MockGrantRepo::new());
        let dev = dev_grant();
        let baseline_grants = vec![dev.clone()];
        let baseline = RbacEvaluator::new(baseline_grants.clone());
        let handle: Arc<ArcSwap<RbacEvaluator>> = Arc::new(ArcSwap::from_pointee(baseline));
        let handle_for_task = handle.clone();
        let mut sig = Signature::from_grants(&baseline_grants);

        // Repo holds a Write grant for the `reader` claim instead.
        let mut reader_writes = reader_grant();
        reader_writes.permission = Permission::Write;
        repo.install_grant(reader_writes);

        let snap = capture(|| {
            let repo = repo.clone();
            async move {
                refresh_once(&handle_for_task, repo.as_ref(), &mut sig).await;
            }
        });

        // `developer` no longer authorizes Write; `reader` now does.
        let evaluator = handle.load_full();
        let dev_principal = hort_domain::entities::caller::CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "s".into(),
            username: "u".into(),
            email: "e@x".into(),
            claims: vec!["developer".into()],
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        };
        let reader_principal = hort_domain::entities::caller::CallerPrincipal {
            claims: vec!["reader".into()],
            ..dev_principal.clone()
        };
        assert!(!evaluator.authorize(&dev_principal, Permission::Write, None));
        assert!(evaluator.authorize(&reader_principal, Permission::Write, None));

        let entries = snap.into_vec();
        assert!(find(
            &entries,
            MetricKind::Counter,
            METRIC_NAME,
            &[("result", RESULT_SUCCESS)]
        )
        .is_some());
    }

    // =====================================================================
    // run_loop — shutdown cancellation
    // =====================================================================

    #[test]
    fn run_loop_exits_within_100ms_of_shutdown_token_cancel() {
        // Drive the loop on a current-thread runtime with a large
        // interval so only the shutdown arm of the `select!` can fire.
        // Cancel the token immediately; the task must exit within the
        // 100 ms bound.
        let repo = Arc::new(MockGrantRepo::new());
        let handle = empty_handle();
        let shutdown = CancellationToken::new();
        let shutdown_for_task = shutdown.clone();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let task = tokio::spawn(run_loop(
                    handle,
                    repo,
                    Signature::default(),
                    Duration::from_secs(3600),
                    shutdown_for_task,
                ));

                // Give the task a tick to enter the jitter sleep, then
                // cancel. The task must observe the cancellation and
                // return — both the jitter sleep and the interval sleep
                // wrap in `select!` arms on `shutdown.cancelled()`.
                tokio::time::sleep(Duration::from_millis(5)).await;
                shutdown.cancel();

                tokio::time::timeout(Duration::from_millis(100), task)
                    .await
                    .expect("rbac refresh task did not exit within 100ms of cancel")
                    .expect("refresh task panicked");
            });
    }

    #[test]
    fn run_loop_polls_at_least_once_before_shutdown() {
        // Use a tight interval so the main loop fires at least one
        // poll after the initial jitter. This proves the poll path
        // actually runs, not just the shutdown arm.
        let repo = Arc::new(MockGrantRepo::new());
        let handle = empty_handle();
        let shutdown = CancellationToken::new();
        let shutdown_for_task = shutdown.clone();
        let repo_for_assertion = repo.clone();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let task = tokio::spawn(run_loop(
                    handle,
                    repo,
                    Signature::default(),
                    Duration::from_millis(10),
                    shutdown_for_task,
                ));
                // Generous wait — jitter can be up to JITTER_MAX_MS, but
                // the mock is in-memory and the loop will catch up
                // quickly once jitter elapses. We're not bounded by the
                // interval, only by jitter.
                tokio::time::sleep(Duration::from_millis(JITTER_MAX_MS + 50)).await;
                shutdown.cancel();
                let _ = tokio::time::timeout(Duration::from_millis(100), task).await;
            });

        assert!(
            repo_for_assertion.list_calls() >= 1,
            "expected at least one poll; got {}",
            repo_for_assertion.list_calls()
        );
    }

    // =====================================================================
    // Signature / SnapshotDiff — pure unit tests
    // =====================================================================

    #[test]
    fn signature_diff_against_empty_counts_everything_as_added() {
        let grants = vec![dev_grant()];
        let sig = Signature::from_grants(&grants);
        let diff = sig.diff(&Signature::default());
        assert_eq!(diff.added_grants, 1);
        assert_eq!(diff.removed_grants, 0);
        assert!(!diff.is_unchanged());
    }

    #[test]
    fn signature_diff_identical_snapshots_is_unchanged() {
        let grants = vec![dev_grant()];
        let a = Signature::from_grants(&grants);
        let b = Signature::from_grants(&grants);
        assert!(a.diff(&b).is_unchanged());
    }

    #[test]
    fn signature_diff_empty_against_empty_is_unchanged() {
        let diff = Signature::default().diff(&Signature::default());
        assert!(diff.is_unchanged());
    }

    #[test]
    fn signature_ignores_grant_id_changes() {
        // Re-seeding the same grant with a new uuid must NOT register
        // as a diff — grant_keys excludes the id field by design
        // (operators replaying gitops config don't want a flood of
        // `success` reloads).
        let mut grant_a = dev_grant();
        let mut grant_b = grant_a.clone();
        grant_a.id = Uuid::new_v4();
        grant_b.id = Uuid::new_v4();
        let sig_a = Signature::from_grants(&[grant_a]);
        let sig_b = Signature::from_grants(&[grant_b]);
        assert_eq!(sig_a, sig_b);
        assert!(sig_a.diff(&sig_b).is_unchanged());
    }

    #[test]
    fn signature_claims_subject_is_order_insensitive() {
        // The evaluator's `Claims` subset match is
        // order/multiplicity-insensitive, so the signature normalises
        // `["a","b"]` and `["b","a","b"]` to the same key — replaying a
        // reordered claim list must NOT register as a structural change.
        let base = dev_grant();
        let mut g1 = base.clone();
        g1.subject = GrantSubject::Claims(vec!["a".into(), "b".into()]);
        let mut g2 = base;
        g2.subject = GrantSubject::Claims(vec!["b".into(), "a".into(), "b".into()]);
        let sig1 = Signature::from_grants(&[g1]);
        let sig2 = Signature::from_grants(&[g2]);
        assert_eq!(sig1, sig2);
        assert!(sig1.diff(&sig2).is_unchanged());
    }

    #[test]
    fn signature_detects_removed_grant() {
        let before = Signature::from_grants(&[dev_grant()]);
        let after = Signature::from_grants(&[]);
        let diff = after.diff(&before);
        assert_eq!(diff.removed_grants, 1);
        assert_eq!(diff.added_grants, 0);
        assert!(!diff.is_unchanged());
    }

    #[test]
    fn signature_user_subject_keyed_by_uuid() {
        // A `GrantSubject::User` grant is keyed by its bare uuid; two
        // grants for distinct users are distinct keys, identical users
        // collapse.
        let uid_a = Uuid::new_v4();
        let uid_b = Uuid::new_v4();
        let mut g_a = dev_grant();
        g_a.subject = GrantSubject::User(uid_a);
        let mut g_b = dev_grant();
        g_b.subject = GrantSubject::User(uid_b);
        let mut g_a2 = dev_grant();
        g_a2.subject = GrantSubject::User(uid_a);

        let sig_two = Signature::from_grants(&[g_a.clone(), g_b]);
        let sig_one = Signature::from_grants(&[g_a, g_a2]);
        // Two distinct users → two keys; the {a,a} set collapses to one.
        assert_eq!(sig_two.diff(&Signature::default()).added_grants, 2);
        assert_eq!(sig_one.diff(&Signature::default()).added_grants, 1);
    }

    // =====================================================================
    // initial_jitter — within-bounds property
    // =====================================================================

    #[test]
    fn initial_jitter_is_bounded_below_max() {
        // Sample the RNG a handful of times; every draw must be strictly
        // less than the documented cap.
        for _ in 0..16 {
            let j = initial_jitter();
            assert!(
                j.as_millis() < u128::from(JITTER_MAX_MS),
                "jitter {}ms exceeded cap {}ms",
                j.as_millis(),
                JITTER_MAX_MS
            );
        }
    }
}
