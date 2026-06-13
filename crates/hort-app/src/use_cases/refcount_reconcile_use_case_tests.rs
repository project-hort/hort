//! `RefcountReconcileUseCase::sweep_drift` unit tests.
//!
//! `hort-app` is the 100%-coverage tier (mock all ports). Every drift
//! case is pinned here with its own
//! test:
//!
//! - missing `primary_content` → created;
//! - mis-targeted `primary_content` → repaired;
//! - missing / mis-targeted `metadata_blob` → upserted;
//! - stale row for a `rejected` source → deleted;
//! - clean projection → no-op (zero repairs);
//! - re-run idempotency → second pass is a no-op;
//! - multi-repo iteration + per-repo `info!` summary shape;
//! - per-repo scan error is recorded and the sweep continues;
//! - per-repair apply error is recorded and the sweep continues.

use std::sync::Arc;
use std::sync::Mutex;

use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::refcount_reconcile::{RefcountReconcilePort, RefcountRepair, RepoDrift};
use hort_domain::ports::BoxFuture;
use hort_domain::types::ContentHash;

use crate::use_cases::refcount_reconcile_use_case::RefcountReconcileUseCase;

const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const HASH_B: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

fn hash(s: &str) -> ContentHash {
    s.parse().unwrap()
}

// ---------------------------------------------------------------------------
// MockRefcountReconcilePort
//
// `scan_repo_drift` returns a per-repo queue of drift-snapshots: the
// first call for a repo pops the front, subsequent calls return the
// converged (empty) state. That models the real adapter, where the
// first sweep observes drift and a re-run (after `apply_repair` has
// healed the projection) observes none — exactly the idempotency /
// re-run contract.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockRefcountReconcilePort {
    repos: Mutex<Vec<Uuid>>,
    repos_err: Mutex<bool>,
    /// Per-repo FIFO of drift snapshots. Pop on each `scan_repo_drift`;
    /// empty/exhausted → converged (empty `RepoDrift`).
    drift: Mutex<std::collections::HashMap<Uuid, std::collections::VecDeque<RepoDrift>>>,
    scan_err_for: Mutex<Option<Uuid>>,
    apply_err_for: Mutex<Option<Uuid>>,
    applied: Mutex<Vec<(Uuid, RefcountRepair)>>,
}

impl MockRefcountReconcilePort {
    fn new() -> Self {
        Self::default()
    }
    fn with_repos(self, ids: Vec<Uuid>) -> Self {
        *self.repos.lock().unwrap() = ids;
        self
    }
    fn with_repos_err(self) -> Self {
        *self.repos_err.lock().unwrap() = true;
        self
    }
    /// Queue one drift snapshot for `repo`. Call twice to model
    /// "first scan drifted, second scan still drifted" — but the
    /// idempotency test queues drift once then relies on the
    /// exhausted-queue → empty behaviour for the re-run.
    fn push_drift(self, repo: Uuid, drift: RepoDrift) -> Self {
        self.drift
            .lock()
            .unwrap()
            .entry(repo)
            .or_default()
            .push_back(drift);
        self
    }
    fn with_scan_err_for(self, repo: Uuid) -> Self {
        *self.scan_err_for.lock().unwrap() = Some(repo);
        self
    }
    fn with_apply_err_for(self, repo: Uuid) -> Self {
        *self.apply_err_for.lock().unwrap() = Some(repo);
        self
    }
    fn applied(&self) -> Vec<(Uuid, RefcountRepair)> {
        self.applied.lock().unwrap().clone()
    }
}

impl RefcountReconcilePort for MockRefcountReconcilePort {
    fn list_repository_ids(&self) -> BoxFuture<'_, DomainResult<Vec<Uuid>>> {
        Box::pin(async move {
            if *self.repos_err.lock().unwrap() {
                return Err(DomainError::Invariant("repo list failed".into()));
            }
            Ok(self.repos.lock().unwrap().clone())
        })
    }

    fn scan_repo_drift(&self, repo_id: Uuid) -> BoxFuture<'_, DomainResult<RepoDrift>> {
        Box::pin(async move {
            if *self.scan_err_for.lock().unwrap() == Some(repo_id) {
                return Err(DomainError::Invariant("scan failed".into()));
            }
            let mut guard = self.drift.lock().unwrap();
            let popped = guard
                .get_mut(&repo_id)
                .and_then(std::collections::VecDeque::pop_front);
            Ok(popped.unwrap_or_default())
        })
    }

    fn apply_repair<'a>(
        &'a self,
        repo_id: Uuid,
        repair: &'a RefcountRepair,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            if *self.apply_err_for.lock().unwrap() == Some(repo_id) {
                return Err(DomainError::Invariant("repair failed".into()));
            }
            self.applied.lock().unwrap().push((repo_id, repair.clone()));
            Ok(())
        })
    }
}

fn uc(port: Arc<MockRefcountReconcilePort>) -> RefcountReconcileUseCase {
    RefcountReconcileUseCase::new(port)
}

// ---------------------------------------------------------------------------
// Drift case: missing primary_content → CreatePrimaryContent applied
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_primary_content_is_created() {
    let repo = Uuid::new_v4();
    let art = Uuid::new_v4();
    let port = Arc::new(
        MockRefcountReconcilePort::new()
            .with_repos(vec![repo])
            .push_drift(
                repo,
                RepoDrift {
                    repairs: vec![RefcountRepair::CreatePrimaryContent {
                        source_artifact_id: art,
                        expected_hash: hash(HASH_A),
                    }],
                },
            ),
    );
    let summary = uc(port.clone()).sweep_drift().await.unwrap();
    assert_eq!(summary.repos_swept, 1);
    assert_eq!(summary.drift_repaired, 1);
    assert_eq!(summary.errors, 0);
    let applied = port.applied();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].0, repo);
    assert!(matches!(
        &applied[0].1,
        RefcountRepair::CreatePrimaryContent { source_artifact_id, expected_hash }
            if *source_artifact_id == art && *expected_hash == hash(HASH_A)
    ));
}

// ---------------------------------------------------------------------------
// Drift case: mis-targeted primary_content → RepairPrimaryContent applied
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mistargeted_primary_content_is_repaired() {
    let repo = Uuid::new_v4();
    let art = Uuid::new_v4();
    let port = Arc::new(
        MockRefcountReconcilePort::new()
            .with_repos(vec![repo])
            .push_drift(
                repo,
                RepoDrift {
                    repairs: vec![RefcountRepair::RepairPrimaryContent {
                        source_artifact_id: art,
                        found_hash: hash(HASH_B),
                        expected_hash: hash(HASH_A),
                    }],
                },
            ),
    );
    let summary = uc(port.clone()).sweep_drift().await.unwrap();
    assert_eq!(summary.drift_repaired, 1);
    let applied = port.applied();
    assert_eq!(applied.len(), 1);
    assert!(matches!(
        &applied[0].1,
        RefcountRepair::RepairPrimaryContent { found_hash, expected_hash, .. }
            if *found_hash == hash(HASH_B) && *expected_hash == hash(HASH_A)
    ));
}

// ---------------------------------------------------------------------------
// Drift case: missing / mis-targeted metadata_blob → UpsertMetadataBlob
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_metadata_blob_is_upserted() {
    let repo = Uuid::new_v4();
    let art = Uuid::new_v4();
    let port = Arc::new(
        MockRefcountReconcilePort::new()
            .with_repos(vec![repo])
            .push_drift(
                repo,
                RepoDrift {
                    repairs: vec![RefcountRepair::UpsertMetadataBlob {
                        source_artifact_id: art,
                        found_hash: None,
                        expected_hash: hash(HASH_A),
                    }],
                },
            ),
    );
    let summary = uc(port.clone()).sweep_drift().await.unwrap();
    assert_eq!(summary.drift_repaired, 1);
    assert!(matches!(
        &port.applied()[0].1,
        RefcountRepair::UpsertMetadataBlob { found_hash: None, expected_hash, .. }
            if *expected_hash == hash(HASH_A)
    ));
}

// ---------------------------------------------------------------------------
// Drift case: stale row for a rejected source → DeleteRejectedSourceRows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejected_source_rows_are_deleted() {
    let repo = Uuid::new_v4();
    let art = Uuid::new_v4();
    let port = Arc::new(
        MockRefcountReconcilePort::new()
            .with_repos(vec![repo])
            .push_drift(
                repo,
                RepoDrift {
                    repairs: vec![RefcountRepair::DeleteRejectedSourceRows {
                        source_artifact_id: art,
                        kind: "primary_content".into(),
                    }],
                },
            ),
    );
    let summary = uc(port.clone()).sweep_drift().await.unwrap();
    assert_eq!(summary.drift_repaired, 1);
    assert!(matches!(
        &port.applied()[0].1,
        RefcountRepair::DeleteRejectedSourceRows { source_artifact_id, .. }
            if *source_artifact_id == art
    ));
}

// ---------------------------------------------------------------------------
// Clean projection → no-op (zero repairs, no apply calls)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clean_projection_is_a_noop() {
    let repo = Uuid::new_v4();
    // No drift queued → scan returns the converged empty RepoDrift.
    let port = Arc::new(MockRefcountReconcilePort::new().with_repos(vec![repo]));
    let summary = uc(port.clone()).sweep_drift().await.unwrap();
    assert_eq!(summary.repos_swept, 1);
    assert_eq!(summary.drift_repaired, 0);
    assert_eq!(summary.errors, 0);
    assert!(
        port.applied().is_empty(),
        "clean projection must apply no repairs"
    );
}

#[tokio::test]
async fn no_repositories_is_a_noop() {
    let port = Arc::new(MockRefcountReconcilePort::new());
    let summary = uc(port.clone()).sweep_drift().await.unwrap();
    assert_eq!(summary.repos_swept, 0);
    assert_eq!(summary.drift_repaired, 0);
    assert!(port.applied().is_empty());
}

// ---------------------------------------------------------------------------
// Re-run idempotency: a second sweep over a now-converged projection
// applies nothing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn second_sweep_is_idempotent_noop() {
    let repo = Uuid::new_v4();
    let art = Uuid::new_v4();
    // Drift queued ONCE. First sweep pops it and repairs; the queue is
    // then exhausted so the second sweep observes the converged
    // (empty) projection — exactly the real adapter's behaviour after
    // `apply_repair` has healed the rows.
    let port = Arc::new(
        MockRefcountReconcilePort::new()
            .with_repos(vec![repo])
            .push_drift(
                repo,
                RepoDrift {
                    repairs: vec![RefcountRepair::CreatePrimaryContent {
                        source_artifact_id: art,
                        expected_hash: hash(HASH_A),
                    }],
                },
            ),
    );
    let first = uc(port.clone()).sweep_drift().await.unwrap();
    assert_eq!(first.drift_repaired, 1);

    let second = uc(port.clone()).sweep_drift().await.unwrap();
    assert_eq!(second.repos_swept, 1);
    assert_eq!(
        second.drift_repaired, 0,
        "re-run on a converged projection must repair nothing"
    );
    assert_eq!(second.errors, 0);
    // Still exactly one apply from the first pass — the second pass
    // added none.
    assert_eq!(port.applied().len(), 1);
}

// ---------------------------------------------------------------------------
// Multi-repo iteration + mixed drift kinds in one repo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multiple_repos_and_mixed_drift_kinds() {
    let r1 = Uuid::new_v4();
    let r2 = Uuid::new_v4();
    let a1 = Uuid::new_v4();
    let a2 = Uuid::new_v4();
    let a3 = Uuid::new_v4();
    let port = Arc::new(
        MockRefcountReconcilePort::new()
            .with_repos(vec![r1, r2])
            .push_drift(
                r1,
                RepoDrift {
                    repairs: vec![
                        RefcountRepair::CreatePrimaryContent {
                            source_artifact_id: a1,
                            expected_hash: hash(HASH_A),
                        },
                        RefcountRepair::UpsertMetadataBlob {
                            source_artifact_id: a1,
                            found_hash: None,
                            expected_hash: hash(HASH_B),
                        },
                    ],
                },
            )
            .push_drift(
                r2,
                RepoDrift {
                    repairs: vec![
                        RefcountRepair::RepairPrimaryContent {
                            source_artifact_id: a2,
                            found_hash: hash(HASH_A),
                            expected_hash: hash(HASH_B),
                        },
                        RefcountRepair::DeleteRejectedSourceRows {
                            source_artifact_id: a3,
                            kind: "metadata_blob".into(),
                        },
                    ],
                },
            ),
    );
    let summary = uc(port.clone()).sweep_drift().await.unwrap();
    assert_eq!(summary.repos_swept, 2);
    assert_eq!(summary.drift_repaired, 4);
    assert_eq!(summary.errors, 0);
    assert_eq!(port.applied().len(), 4);
}

// ---------------------------------------------------------------------------
// Error paths: a per-repo scan error / per-repair apply error is
// recorded and the sweep CONTINUES (never aborts the whole run).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_repos_error_aborts_with_app_error() {
    let port = Arc::new(MockRefcountReconcilePort::new().with_repos_err());
    let err = uc(port).sweep_drift().await.unwrap_err();
    assert!(err.to_string().contains("repo list failed"));
}

#[tokio::test]
async fn scan_error_on_one_repo_is_recorded_and_sweep_continues() {
    let bad = Uuid::new_v4();
    let good = Uuid::new_v4();
    let art = Uuid::new_v4();
    let port = Arc::new(
        MockRefcountReconcilePort::new()
            .with_repos(vec![bad, good])
            .with_scan_err_for(bad)
            .push_drift(
                good,
                RepoDrift {
                    repairs: vec![RefcountRepair::CreatePrimaryContent {
                        source_artifact_id: art,
                        expected_hash: hash(HASH_A),
                    }],
                },
            ),
    );
    let summary = uc(port.clone()).sweep_drift().await.unwrap();
    assert_eq!(summary.repos_swept, 2);
    assert_eq!(summary.errors, 1, "the bad repo's scan error is counted");
    assert_eq!(
        summary.drift_repaired, 1,
        "the good repo is still swept after the bad one errored"
    );
    assert_eq!(port.applied().len(), 1);
}

#[tokio::test]
async fn apply_error_on_one_repair_is_recorded_and_sweep_continues() {
    let repo = Uuid::new_v4();
    let a1 = Uuid::new_v4();
    let a2 = Uuid::new_v4();
    // Both repairs are queued for the same repo whose apply always
    // errors → both error, the sweep records 2 errors and still
    // returns Ok (per-case error, never fatal).
    let port = Arc::new(
        MockRefcountReconcilePort::new()
            .with_repos(vec![repo])
            .with_apply_err_for(repo)
            .push_drift(
                repo,
                RepoDrift {
                    repairs: vec![
                        RefcountRepair::CreatePrimaryContent {
                            source_artifact_id: a1,
                            expected_hash: hash(HASH_A),
                        },
                        RefcountRepair::CreatePrimaryContent {
                            source_artifact_id: a2,
                            expected_hash: hash(HASH_B),
                        },
                    ],
                },
            ),
    );
    let summary = uc(port.clone()).sweep_drift().await.unwrap();
    assert_eq!(summary.repos_swept, 1);
    assert_eq!(summary.errors, 2);
    assert_eq!(summary.drift_repaired, 0, "neither repair landed");
    assert!(port.applied().is_empty());
}
