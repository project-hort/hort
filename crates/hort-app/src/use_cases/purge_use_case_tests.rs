//! `PurgeUseCase::process_expired` unit tests.
//!
//! `hort-app` is the 100%-coverage tier, so the mocks expose every
//! prepare, storage, checkpoint, and terminal-transition failure seam.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{retention_scheduler_actor, ArtifactPurged, DomainEvent};
use hort_domain::ports::event_store::AppendEvents;
use hort_domain::ports::purge_gc::{PendingPurge, PurgeGcPort, PurgedRef};
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::BoxFuture;
use hort_domain::types::{ByteRange, ContentHash};

use crate::use_cases::purge_use_case::{PurgeUseCase, RefcountReconcileGate};

const HASH_PRIMARY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const HASH_META: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
const HASH_CHILD: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

fn hash(s: &str) -> ContentHash {
    s.parse().unwrap()
}

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).unwrap()
}

fn work(content_hash: ContentHash, refs_remaining: u32) -> PurgedRef {
    PurgedRef {
        content_hash,
        refs_remaining,
        completed: false,
    }
}

struct MockReconcileGate(bool);

impl MockReconcileGate {
    fn converged() -> Arc<Self> {
        Arc::new(Self(true))
    }

    fn not_converged() -> Arc<Self> {
        Arc::new(Self(false))
    }
}

impl RefcountReconcileGate for MockReconcileGate {
    fn is_converged(&self) -> bool {
        self.0
    }
}

#[derive(Default)]
struct MockPurgeGc {
    pending: Mutex<Vec<PendingPurge>>,
    refs: Mutex<HashMap<Uuid, Vec<PurgedRef>>>,
    list_err: AtomicBool,
    purge_err_for: Mutex<HashSet<Uuid>>,
    mark_fail_once_for: Mutex<HashSet<ContentHash>>,
    complete_fail_once: AtomicBool,
    purge_calls: Mutex<Vec<Uuid>>,
    complete_calls: AtomicUsize,
    completed_batches: Mutex<Vec<AppendEvents>>,
    retired: Mutex<HashSet<Uuid>>,
    list_calls: AtomicUsize,
}

impl MockPurgeGc {
    fn new() -> Self {
        Self::default()
    }

    fn with_pending(self, pending: Vec<PendingPurge>) -> Self {
        *self.pending.lock().unwrap() = pending;
        self
    }

    fn with_refs(self, artifact_id: Uuid, refs: Vec<PurgedRef>) -> Self {
        self.refs.lock().unwrap().insert(artifact_id, refs);
        self
    }

    fn with_list_err(self) -> Self {
        self.list_err.store(true, Ordering::SeqCst);
        self
    }

    fn fail_purge_for(self, artifact_id: Uuid) -> Self {
        self.purge_err_for.lock().unwrap().insert(artifact_id);
        self
    }

    fn fail_mark_once_for(self, content_hash: ContentHash) -> Self {
        self.mark_fail_once_for.lock().unwrap().insert(content_hash);
        self
    }

    fn fail_complete_once(self) -> Self {
        self.complete_fail_once.store(true, Ordering::SeqCst);
        self
    }

    fn purge_call_count(&self) -> usize {
        self.purge_calls.lock().unwrap().len()
    }

    fn list_call_count(&self) -> usize {
        self.list_calls.load(Ordering::SeqCst)
    }

    fn complete_call_count(&self) -> usize {
        self.complete_calls.load(Ordering::SeqCst)
    }

    fn is_retired(&self, artifact_id: Uuid) -> bool {
        self.retired.lock().unwrap().contains(&artifact_id)
    }

    fn completed_batches(&self) -> Vec<AppendEvents> {
        self.completed_batches.lock().unwrap().clone()
    }
}

impl PurgeGcPort for MockPurgeGc {
    fn list_pending_purge(&self) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        let fail = self.list_err.load(Ordering::SeqCst);
        let retired = self.retired.lock().unwrap().clone();
        let pending = self
            .pending
            .lock()
            .unwrap()
            .iter()
            .filter(|item| !retired.contains(&item.artifact_id))
            .cloned()
            .collect();
        Box::pin(async move {
            if fail {
                Err(DomainError::Invariant("pending list failed".into()))
            } else {
                Ok(pending)
            }
        })
    }

    fn purge_artifact_refs(
        &self,
        artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<PurgedRef>>> {
        self.purge_calls.lock().unwrap().push(artifact_id);
        let fail = self.purge_err_for.lock().unwrap().contains(&artifact_id);
        let refs = self
            .refs
            .lock()
            .unwrap()
            .get(&artifact_id)
            .cloned()
            .unwrap_or_default();
        Box::pin(async move {
            if fail {
                Err(DomainError::Invariant("prepare failed".into()))
            } else {
                Ok(refs)
            }
        })
    }

    fn mark_purge_ref_complete(
        &self,
        artifact_id: Uuid,
        content_hash: &ContentHash,
        _completed_at: DateTime<Utc>,
    ) -> BoxFuture<'_, DomainResult<()>> {
        let fail = self.mark_fail_once_for.lock().unwrap().remove(content_hash);
        if !fail {
            let mut refs = self.refs.lock().unwrap();
            if let Some(item) = refs.get_mut(&artifact_id).and_then(|items| {
                items
                    .iter_mut()
                    .find(|item| item.content_hash == *content_hash)
            }) {
                item.completed = true;
            }
        }
        Box::pin(async move {
            if fail {
                Err(DomainError::Invariant("checkpoint failed".into()))
            } else {
                Ok(())
            }
        })
    }

    fn complete_artifact_purge(
        &self,
        artifact_id: Uuid,
        _retired_at: DateTime<Utc>,
        events: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<()>> {
        self.complete_calls.fetch_add(1, Ordering::SeqCst);
        let fail = self.complete_fail_once.swap(false, Ordering::SeqCst);
        if !fail {
            assert!(self
                .refs
                .lock()
                .unwrap()
                .get(&artifact_id)
                .is_some_and(|refs| refs.iter().all(|item| item.completed)));
            self.completed_batches.lock().unwrap().push(events);
            self.retired.lock().unwrap().insert(artifact_id);
        }
        Box::pin(async move {
            if fail {
                Err(DomainError::Invariant("terminal transition failed".into()))
            } else {
                Ok(())
            }
        })
    }
}

#[derive(Default)]
struct MockStorage {
    present: Mutex<Vec<ContentHash>>,
    transient_fail_once: Mutex<HashSet<ContentHash>>,
    delete_attempts: Mutex<Vec<ContentHash>>,
}

impl MockStorage {
    fn new() -> Self {
        Self::default()
    }

    fn with_present(self, content_hash: ContentHash) -> Self {
        self.present.lock().unwrap().push(content_hash);
        self
    }

    fn fail_delete_once(self, content_hash: ContentHash) -> Self {
        self.transient_fail_once
            .lock()
            .unwrap()
            .insert(content_hash);
        self
    }

    fn delete_attempts(&self) -> Vec<ContentHash> {
        self.delete_attempts.lock().unwrap().clone()
    }
}

impl StoragePort for MockStorage {
    fn put(
        &self,
        _stream: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<hort_domain::ports::storage::PutResult>> {
        Box::pin(async { unreachable!("purge never puts") })
    }

    fn get(
        &self,
        _content_hash: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Box<dyn tokio::io::AsyncRead + Send + Unpin>>> {
        Box::pin(async { unreachable!("purge never gets") })
    }

    fn get_range(
        &self,
        _content_hash: &ContentHash,
        _range: ByteRange,
    ) -> BoxFuture<'_, DomainResult<Box<dyn tokio::io::AsyncRead + Send + Unpin>>> {
        Box::pin(async { unreachable!("purge never range-gets") })
    }

    fn exists(&self, content_hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
        let present = self.present.lock().unwrap().contains(content_hash);
        Box::pin(async move { Ok(present) })
    }

    fn delete(&self, content_hash: &ContentHash) -> BoxFuture<'_, DomainResult<()>> {
        self.delete_attempts
            .lock()
            .unwrap()
            .push(content_hash.clone());
        let fail = self
            .transient_fail_once
            .lock()
            .unwrap()
            .remove(content_hash);
        let present = if fail {
            false
        } else {
            let mut present = self.present.lock().unwrap();
            present
                .iter()
                .position(|item| item == content_hash)
                .map(|index| present.remove(index))
                .is_some()
        };
        let id = content_hash.to_string();
        Box::pin(async move {
            if fail {
                Err(DomainError::Invariant(format!(
                    "transient delete failure: {id}"
                )))
            } else if present {
                Ok(())
            } else {
                Err(DomainError::NotFound {
                    entity: "content",
                    id,
                })
            }
        })
    }

    fn size_of(&self, content_hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
        let id = content_hash.to_string();
        Box::pin(async move {
            Err(DomainError::NotFound {
                entity: "content",
                id,
            })
        })
    }
}

struct Harness {
    uc: PurgeUseCase,
    gc: Arc<MockPurgeGc>,
    storage: Arc<MockStorage>,
}

fn build(gc: MockPurgeGc, storage: MockStorage, gate: Arc<MockReconcileGate>) -> Harness {
    let gc = Arc::new(gc);
    let storage = Arc::new(storage);
    let uc = PurgeUseCase::new(gc.clone(), storage.clone(), gate);
    Harness { uc, gc, storage }
}

fn purged_events(gc: &MockPurgeGc) -> Vec<ArtifactPurged> {
    gc.completed_batches()
        .into_iter()
        .flat_map(|batch| batch.events)
        .filter_map(|event| match event.event {
            DomainEvent::ArtifactPurged(event) => Some(event),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn refuses_to_run_when_reconcile_not_converged() {
    let artifact_id = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new().with_pending(vec![PendingPurge {
            artifact_id,
            quarantine_status: QuarantineStatus::None,
            tag_targeted: false,
            expired_only_by_keep_last_n: false,
            user_deleted: false,
        }]),
        MockStorage::new(),
        MockReconcileGate::not_converged(),
    );

    let error = h.uc.process_expired(ts(1000)).await.unwrap_err();
    assert!(error.to_string().contains("has not converged"));
    assert_eq!(h.gc.list_call_count(), 0);
    assert_eq!(h.gc.purge_call_count(), 0);
    assert!(h.storage.delete_attempts().is_empty());
}

#[tokio::test]
async fn converged_empty_pending_is_noop() {
    let h = build(
        MockPurgeGc::new(),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );
    assert_eq!(
        h.uc.process_expired(ts(1000)).await.unwrap(),
        Default::default()
    );
    assert_eq!(h.gc.list_call_count(), 1);
}

#[tokio::test]
async fn zero_refcount_deletes_blob_then_retires_with_terminal_event() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id,
                quarantine_status: QuarantineStatus::None,
                tag_targeted: false,
                expired_only_by_keep_last_n: false,
                user_deleted: false,
            }])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)]),
        MockStorage::new().with_present(content_hash.clone()),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.blobs_deleted, 1);
    assert_eq!(summary.purged_events, 1);
    assert_eq!(summary.errors, 0);
    assert!(h.gc.is_retired(artifact_id));
    let batches = h.gc.completed_batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].events.len(), 1);
    assert_eq!(batches[0].actor, retention_scheduler_actor());
    let events = purged_events(&h.gc);
    assert_eq!(events[0].artifact_id, artifact_id);
    assert_eq!(events[0].content_hash, content_hash);
    assert_eq!(events[0].refs_remaining, 0);
    assert_eq!(events[0].purged_at, ts(2000));
}

#[tokio::test]
async fn shared_blob_is_kept_but_artifact_is_retired() {
    let artifact_id = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id,
                quarantine_status: QuarantineStatus::Released,
                tag_targeted: false,
                expired_only_by_keep_last_n: false,
                user_deleted: false,
            }])
            .with_refs(artifact_id, vec![work(hash(HASH_PRIMARY), 3)]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(3000)).await.unwrap();
    assert_eq!(summary.blobs_deleted, 0);
    assert_eq!(summary.blobs_kept, 1);
    assert_eq!(summary.purged_events, 1);
    assert!(h.storage.delete_attempts().is_empty());
    assert!(h.gc.is_retired(artifact_id));
    assert_eq!(purged_events(&h.gc)[0].refs_remaining, 3);
}

#[tokio::test]
async fn all_hashes_land_in_one_terminal_batch() {
    let artifact_id = Uuid::new_v4();
    let primary = hash(HASH_PRIMARY);
    let metadata = hash(HASH_META);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id,
                quarantine_status: QuarantineStatus::None,
                tag_targeted: false,
                expired_only_by_keep_last_n: false,
                user_deleted: false,
            }])
            .with_refs(
                artifact_id,
                vec![work(primary.clone(), 0), work(metadata.clone(), 1)],
            ),
        MockStorage::new().with_present(primary),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(4000)).await.unwrap();
    assert_eq!(summary.blobs_deleted, 1);
    assert_eq!(summary.blobs_kept, 1);
    assert_eq!(summary.purged_events, 2);
    assert_eq!(h.gc.completed_batches()[0].events.len(), 2);
    let by_hash: HashMap<_, _> = purged_events(&h.gc)
        .into_iter()
        .map(|event| (event.content_hash, event.refs_remaining))
        .collect();
    assert_eq!(by_hash.get(&hash(HASH_PRIMARY)), Some(&0));
    assert_eq!(by_hash.get(&metadata), Some(&1));
}

#[tokio::test]
async fn second_hash_failure_withholds_entire_terminal_transition_then_retries() {
    let artifact_id = Uuid::new_v4();
    let first = hash(HASH_PRIMARY);
    let second = hash(HASH_CHILD);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id,
                quarantine_status: QuarantineStatus::None,
                tag_targeted: false,
                expired_only_by_keep_last_n: false,
                user_deleted: false,
            }])
            .with_refs(
                artifact_id,
                vec![work(first.clone(), 0), work(second.clone(), 0)],
            ),
        MockStorage::new()
            .with_present(first.clone())
            .with_present(second.clone())
            .fail_delete_once(second.clone()),
        MockReconcileGate::converged(),
    );

    let first_run = h.uc.process_expired(ts(5000)).await.unwrap();
    assert_eq!(first_run.errors, 1);
    assert_eq!(first_run.purged_events, 0);
    assert_eq!(h.gc.complete_call_count(), 0);
    assert!(!h.gc.is_retired(artifact_id));
    assert!(purged_events(&h.gc).is_empty());

    let retry = h.uc.process_expired(ts(6000)).await.unwrap();
    assert_eq!(retry.errors, 0);
    assert_eq!(retry.purged_events, 2);
    assert!(h.gc.is_retired(artifact_id));
    assert_eq!(purged_events(&h.gc).len(), 2);
    assert_eq!(
        h.storage.delete_attempts(),
        vec![first, second.clone(), second],
        "the checkpointed first hash is not re-deleted on retry"
    );
}

#[tokio::test]
async fn completed_primary_does_not_hide_outstanding_oci_child() {
    let artifact_id = Uuid::new_v4();
    let primary = PurgedRef {
        content_hash: hash(HASH_PRIMARY),
        refs_remaining: 0,
        completed: true,
    };
    let child = hash(HASH_CHILD);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id,
                quarantine_status: QuarantineStatus::None,
                tag_targeted: false,
                expired_only_by_keep_last_n: false,
                user_deleted: false,
            }])
            .with_refs(artifact_id, vec![primary, work(child.clone(), 0)]),
        MockStorage::new().with_present(child.clone()),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(6100)).await.unwrap();
    assert_eq!(summary.purged_events, 2);
    assert_eq!(h.storage.delete_attempts(), vec![child]);
    assert!(h.gc.is_retired(artifact_id));
}

#[tokio::test]
async fn absent_storage_is_an_idempotent_success() {
    let artifact_id = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id,
                quarantine_status: QuarantineStatus::None,
                tag_targeted: false,
                expired_only_by_keep_last_n: false,
                user_deleted: false,
            }])
            .with_refs(artifact_id, vec![work(hash(HASH_PRIMARY), 0)]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(7000)).await.unwrap();
    assert_eq!(summary.errors, 0);
    assert_eq!(summary.blobs_deleted, 1);
    assert_eq!(summary.purged_events, 1);
}

#[tokio::test]
async fn protected_artifacts_are_never_prepared() {
    for status in [
        QuarantineStatus::Quarantined,
        QuarantineStatus::Rejected,
        QuarantineStatus::ScanIndeterminate,
    ] {
        let artifact_id = Uuid::new_v4();
        let h = build(
            MockPurgeGc::new().with_pending(vec![PendingPurge {
                artifact_id,
                quarantine_status: status,
                tag_targeted: false,
                expired_only_by_keep_last_n: false,
                user_deleted: false,
            }]),
            MockStorage::new(),
            MockReconcileGate::converged(),
        );

        let summary = h.uc.process_expired(ts(8000)).await.unwrap();
        assert_eq!(summary.skipped_protected, 1);
        assert_eq!(h.gc.purge_call_count(), 0);
        assert!(!h.gc.is_retired(artifact_id));
    }
}

#[tokio::test]
async fn list_failure_aborts_the_sweep() {
    let h = build(
        MockPurgeGc::new().with_list_err(),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );
    assert!(h.uc.process_expired(ts(9000)).await.is_err());
}

#[tokio::test]
async fn prepare_failure_is_per_artifact_and_sweep_continues() {
    let bad = Uuid::new_v4();
    let good = Uuid::new_v4();
    let content_hash = hash(HASH_META);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![
                PendingPurge {
                    artifact_id: bad,
                    quarantine_status: QuarantineStatus::None,
                    tag_targeted: false,
                    expired_only_by_keep_last_n: false,
                    user_deleted: false,
                },
                PendingPurge {
                    artifact_id: good,
                    quarantine_status: QuarantineStatus::None,
                    tag_targeted: false,
                    expired_only_by_keep_last_n: false,
                    user_deleted: false,
                },
            ])
            .with_refs(good, vec![work(content_hash.clone(), 0)])
            .fail_purge_for(bad),
        MockStorage::new().with_present(content_hash),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(9100)).await.unwrap();
    assert_eq!(summary.errors, 1);
    assert_eq!(summary.purged_events, 1);
    assert!(!h.gc.is_retired(bad));
    assert!(h.gc.is_retired(good));
}

#[tokio::test]
async fn empty_worklist_is_a_noop() {
    let artifact_id = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id,
                quarantine_status: QuarantineStatus::None,
                tag_targeted: false,
                expired_only_by_keep_last_n: false,
                user_deleted: false,
            }])
            .with_refs(artifact_id, Vec::new()),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(9150)).await.unwrap();
    assert_eq!(summary.artifacts_visited, 1);
    assert_eq!(summary.purged_events, 0);
    assert_eq!(h.gc.complete_call_count(), 0);
}

#[tokio::test]
async fn checkpoint_failure_withholds_terminal_transition_and_retries() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id,
                quarantine_status: QuarantineStatus::None,
                tag_targeted: false,
                expired_only_by_keep_last_n: false,
                user_deleted: false,
            }])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
            .fail_mark_once_for(content_hash),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let first = h.uc.process_expired(ts(9200)).await.unwrap();
    assert_eq!(first.errors, 1);
    assert_eq!(first.purged_events, 0);
    assert!(!h.gc.is_retired(artifact_id));

    let retry = h.uc.process_expired(ts(9300)).await.unwrap();
    assert_eq!(retry.errors, 0);
    assert_eq!(retry.purged_events, 1);
    assert!(h.gc.is_retired(artifact_id));
}

#[tokio::test]
async fn terminal_transition_failure_retries_without_repeating_storage() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id,
                quarantine_status: QuarantineStatus::None,
                tag_targeted: false,
                expired_only_by_keep_last_n: false,
                user_deleted: false,
            }])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
            .fail_complete_once(),
        MockStorage::new().with_present(content_hash.clone()),
        MockReconcileGate::converged(),
    );

    let first = h.uc.process_expired(ts(9400)).await.unwrap();
    assert_eq!(first.errors, 1);
    assert_eq!(first.purged_events, 0);
    assert!(!h.gc.is_retired(artifact_id));

    let retry = h.uc.process_expired(ts(9500)).await.unwrap();
    assert_eq!(retry.errors, 0);
    assert_eq!(retry.purged_events, 1);
    assert_eq!(h.storage.delete_attempts(), vec![content_hash]);
    assert!(h.gc.is_retired(artifact_id));
}

mod metrics_emission_tests {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    type SnapEntry = (
        metrics_util::CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn counter(snapshot: &[SnapEntry], result: &str) -> Option<u64> {
        snapshot.iter().find_map(|(key, _, _, value)| {
            let labels: HashMap<&str, &str> = key
                .key()
                .labels()
                .map(|label| (label.key(), label.value()))
                .collect();
            if key.key().name() == "hort_retention_purged_total"
                && labels.get("result") == Some(&result)
            {
                if let DebugValue::Counter(value) = value {
                    return Some(*value);
                }
            }
            None
        })
    }

    #[test]
    fn purged_total_records_terminal_results_and_storage_error() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let success = Uuid::new_v4();
                    let kept = Uuid::new_v4();
                    let failed = Uuid::new_v4();
                    let success_hash = hash(HASH_PRIMARY);
                    let failed_hash = hash(HASH_CHILD);
                    let h = build(
                        MockPurgeGc::new()
                            .with_pending(vec![
                                PendingPurge {
                                    artifact_id: success,
                                    quarantine_status: QuarantineStatus::None,
                                    tag_targeted: false,
                                    expired_only_by_keep_last_n: false,
                                    user_deleted: false,
                                },
                                PendingPurge {
                                    artifact_id: kept,
                                    quarantine_status: QuarantineStatus::None,
                                    tag_targeted: false,
                                    expired_only_by_keep_last_n: false,
                                    user_deleted: false,
                                },
                                PendingPurge {
                                    artifact_id: failed,
                                    quarantine_status: QuarantineStatus::None,
                                    tag_targeted: false,
                                    expired_only_by_keep_last_n: false,
                                    user_deleted: false,
                                },
                            ])
                            .with_refs(success, vec![work(success_hash.clone(), 0)])
                            .with_refs(kept, vec![work(hash(HASH_META), 2)])
                            .with_refs(failed, vec![work(failed_hash.clone(), 0)]),
                        MockStorage::new()
                            .with_present(success_hash)
                            .with_present(failed_hash.clone())
                            .fail_delete_once(failed_hash),
                        MockReconcileGate::converged(),
                    );
                    h.uc.process_expired(ts(1)).await.unwrap();
                });
        });

        let snapshot = snapshotter.snapshot().into_vec();
        assert_eq!(counter(&snapshot, "success"), Some(1));
        assert_eq!(counter(&snapshot, "blob_kept"), Some(1));
        assert_eq!(counter(&snapshot, "storage_error"), Some(1));
    }
}

// ===========================================================================
// KeepLastN tag exemption, re-asked at purge time
// ===========================================================================

fn pending(artifact_id: Uuid, tag_targeted: bool, keep_last_n_only: bool) -> PendingPurge {
    PendingPurge {
        artifact_id,
        quarantine_status: QuarantineStatus::Released,
        tag_targeted,
        expired_only_by_keep_last_n: keep_last_n_only,
        user_deleted: false,
    }
}

/// A caller-deleted artifact: `ArtifactDeleted` is its only work item,
/// so there is no expiry decision and `expired_only_by_keep_last_n` is
/// vacuously `true` — the shape the tag exemption has to survive.
fn pending_user_deleted(artifact_id: Uuid, tag_targeted: bool) -> PendingPurge {
    PendingPurge {
        artifact_id,
        quarantine_status: QuarantineStatus::Released,
        tag_targeted,
        expired_only_by_keep_last_n: true,
        user_deleted: true,
    }
}

/// Walk the interval the two cron sweeps leave open: the artifact was
/// expired by `KeepLastN` at 03:00 with no ref on it, a tag was set at
/// 03:30, and the purge runs at 04:00. Nothing re-runs the predicate,
/// so the purge itself has to re-ask — the steady-state fixtures below
/// pass without this and that is exactly why it is its own test.
#[tokio::test]
async fn a_tag_set_between_expiry_and_purge_saves_the_artifact() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            // The ref set during the interval is visible to the sweep
            // that reads the work set, not to the expiry that predates it.
            .with_pending(vec![pending(artifact_id, true, true)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(8000)).await.unwrap();

    assert_eq!(summary.artifacts_visited, 1);
    assert_eq!(summary.skipped_tag_exempt, 1);
    assert_eq!(summary.blobs_deleted, 0);
    assert_eq!(summary.purged_events, 0);
    // Nothing destructive ran, and the decision is retained: the
    // artifact is purged on a later sweep once the tag moves.
    assert_eq!(h.gc.purge_call_count(), 0);
    assert!(h.storage.delete_attempts().is_empty());
    assert!(!h.gc.is_retired(artifact_id));
}

#[tokio::test]
async fn an_untagged_keep_last_n_expiry_is_purged_normally() {
    let artifact_id = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![pending(artifact_id, false, true)])
            .with_refs(artifact_id, vec![work(hash(HASH_PRIMARY), 0)]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(8000)).await.unwrap();

    assert_eq!(summary.skipped_tag_exempt, 0);
    assert_eq!(summary.blobs_deleted, 1);
    assert!(h.gc.is_retired(artifact_id));
}

#[tokio::test]
async fn a_tagged_artifact_expired_by_another_predicate_is_still_purged() {
    // The exemption belongs to KeepLastN alone. An age- or
    // security-driven decision stands: the artifact is purged even
    // while a ref points at it.
    let artifact_id = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![pending(artifact_id, true, false)])
            .with_refs(artifact_id, vec![work(hash(HASH_PRIMARY), 0)]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(8000)).await.unwrap();

    assert_eq!(summary.skipped_tag_exempt, 0);
    assert_eq!(summary.blobs_deleted, 1);
    assert!(h.gc.is_retired(artifact_id));
}

// ===========================================================================
// The caller-facing delete as a byte-release work item
// ===========================================================================

/// A delete carries no expiry decision, so nothing in the sweep may
/// require one: the edges are released and the blob is collected exactly
/// as for an expiry.
#[tokio::test]
async fn a_user_deleted_artifact_releases_its_refs_and_its_blob() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![pending_user_deleted(artifact_id, false)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(9000)).await.unwrap();

    assert_eq!(summary.artifacts_visited, 1);
    assert_eq!(summary.user_deletes_visited, 1);
    assert_eq!(summary.blobs_deleted, 1);
    assert_eq!(summary.purged_events, 1);
    assert_eq!(summary.skipped_tag_exempt, 0);
    assert_eq!(summary.errors, 0);
    assert_eq!(h.gc.purge_call_count(), 1);
    assert_eq!(h.storage.delete_attempts(), vec![content_hash]);
    assert!(h.gc.is_retired(artifact_id));
    let purged = purged_events(&h.gc);
    assert_eq!(purged.len(), 1);
    assert_eq!(purged[0].refs_remaining, 0);
    assert_eq!(purged[0].purged_at, ts(9000));
}

/// Bytes another artifact still references survive the delete: the
/// reference is removed, the blob is kept, and `refs_remaining` records
/// why.
#[tokio::test]
async fn a_user_delete_over_shared_bytes_keeps_the_blob() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![pending_user_deleted(artifact_id, false)])
            .with_refs(artifact_id, vec![work(content_hash, 1)]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(9000)).await.unwrap();

    assert_eq!(summary.user_deletes_visited, 1);
    assert_eq!(summary.blobs_kept, 1);
    assert_eq!(summary.blobs_deleted, 0);
    assert!(h.storage.delete_attempts().is_empty());
    assert_eq!(purged_events(&h.gc)[0].refs_remaining, 1);
}

/// The `KeepLastN` tag exemption must not swallow a delete. The flag it
/// reads is vacuously `true` for an artifact with no expiry decision, so
/// a tagged delete would otherwise be skipped forever by a rule for a
/// policy that never ran.
#[tokio::test]
async fn a_tagged_user_delete_is_not_tag_exempt() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![pending_user_deleted(artifact_id, true)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(9000)).await.unwrap();

    assert_eq!(summary.skipped_tag_exempt, 0);
    assert_eq!(summary.blobs_deleted, 1);
    assert_eq!(h.storage.delete_attempts(), vec![content_hash]);
    assert!(h.gc.is_retired(artifact_id));
}

/// A `KeepLastN` expiry a delete then joined is purged: the delete is the
/// instruction that stands, exactly as an age-driven expiry would be.
#[tokio::test]
async fn a_tagged_keep_last_n_expiry_that_was_also_deleted_is_purged() {
    let artifact_id = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id,
                quarantine_status: QuarantineStatus::Released,
                tag_targeted: true,
                expired_only_by_keep_last_n: true,
                user_deleted: true,
            }])
            .with_refs(artifact_id, vec![work(hash(HASH_PRIMARY), 0)]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(9000)).await.unwrap();

    assert_eq!(summary.skipped_tag_exempt, 0);
    assert_eq!(summary.blobs_deleted, 1);
    assert!(h.gc.is_retired(artifact_id));
}

/// Invariant 1 does not bend for a delete. An artifact is deletable
/// whatever its quarantine status, so evidence really can arrive here
/// carrying a delete work item — and it must still keep its bytes.
#[tokio::test]
async fn a_user_deleted_evidence_artifact_is_still_not_collected() {
    for status in [
        QuarantineStatus::Quarantined,
        QuarantineStatus::Rejected,
        QuarantineStatus::ScanIndeterminate,
    ] {
        let artifact_id = Uuid::new_v4();
        let h = build(
            MockPurgeGc::new()
                .with_pending(vec![PendingPurge {
                    artifact_id,
                    quarantine_status: status,
                    tag_targeted: false,
                    expired_only_by_keep_last_n: true,
                    user_deleted: true,
                }])
                .with_refs(artifact_id, vec![work(hash(HASH_PRIMARY), 0)]),
            MockStorage::new(),
            MockReconcileGate::converged(),
        );

        let summary = h.uc.process_expired(ts(9000)).await.unwrap();

        assert_eq!(summary.skipped_protected, 1, "{status} must be skipped");
        assert_eq!(summary.user_deletes_visited, 1);
        assert_eq!(summary.blobs_deleted, 0);
        assert_eq!(h.gc.purge_call_count(), 0);
        assert!(h.storage.delete_attempts().is_empty());
        assert!(!h.gc.is_retired(artifact_id));
    }
}

/// The two work-item classes are counted separately so an operator can
/// attribute a sweep's destructive work — a deployment with no retention
/// policy at all still collects here.
#[tokio::test]
async fn the_summary_separates_delete_driven_from_expiry_driven_work() {
    let deleted = Uuid::new_v4();
    let expired = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![
                pending_user_deleted(deleted, false),
                pending(expired, false, false),
            ])
            .with_refs(deleted, vec![work(hash(HASH_PRIMARY), 0)])
            .with_refs(expired, vec![work(hash(HASH_META), 0)]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(9000)).await.unwrap();

    assert_eq!(summary.artifacts_visited, 2);
    assert_eq!(summary.user_deletes_visited, 1);
    assert_eq!(summary.blobs_deleted, 2);
    assert_eq!(summary.purged_events, 2);
}
