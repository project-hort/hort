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
use hort_domain::ports::purge_gc::{
    BlobReclaim, BlobReclaimGuard, PendingPurge, PurgeGcPort, PurgePreparation, PurgedRef,
};
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::BoxFuture;
use hort_domain::types::{ByteRange, ContentHash};

use crate::use_cases::purge_use_case::{
    PurgeUseCase, RefcountReconcileGate, BATCH_SIZE, MAX_BATCHES_PER_TICK,
};

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
    purged: Mutex<HashSet<Uuid>>,
    /// `artifacts.deleted_at`, as written by `purge_artifact_refs` —
    /// the retirement the preparation transaction performs, keyed by
    /// artifact and holding the timestamp so a retry can be shown to
    /// keep the first one (the adapter's `COALESCE`).
    retired: Mutex<HashMap<Uuid, DateTime<Utc>>>,
    list_calls: AtomicUsize,
    /// Per-artifact script for `purge_artifact_refs`. Absent ⇒
    /// `Prepared` with whatever [`Self::refs`] holds. Present ⇒ the
    /// answer the adapter gives when the read it takes under the
    /// artifact lock disagrees with the page row the sweep is carrying.
    prepare_script: Mutex<HashMap<Uuid, PurgePreparation>>,
    /// Per-hash script for `begin_blob_reclaim`. Absent ⇒ `Granted`.
    reclaim_script: Mutex<HashMap<ContentHash, Reclaim>>,
    reclaim_calls: Mutex<Vec<(Uuid, ContentHash)>>,
    /// Ordered trace of lease/delete/release, shared with
    /// [`MockStorage`] — the only way to assert that the delete happens
    /// *between* the two, which is the property the fix rests on.
    trace: Arc<Mutex<Vec<String>>>,
    /// Leases handed out and not yet released.
    outstanding_leases: Arc<AtomicUsize>,
}

/// What [`MockPurgeGc::begin_blob_reclaim`] should answer for a hash.
#[derive(Clone, Debug)]
enum Reclaim {
    Granted,
    Contended,
    Referenced(u32),
    /// Zero reference rows, but N GC-protected artifacts claim the
    /// hash — the claim the refcount structurally cannot show.
    ProtectedClaim(u32),
    Err,
    /// Granted, but the guard fails to release. The delete still
    /// happened; the sweep must not treat the release failure as a
    /// storage failure.
    GrantedReleaseFails,
}

/// Guard handed back by the mock. Records its release in the shared
/// trace and flips the outstanding-lease flag, so a test can prove the
/// lease is not still held after the sweep returns.
struct MockGuard {
    trace: Arc<Mutex<Vec<String>>>,
    outstanding: Arc<AtomicUsize>,
    fail: bool,
}

impl BlobReclaimGuard for MockGuard {
    fn release(self: Box<Self>) -> BoxFuture<'static, DomainResult<()>> {
        self.trace.lock().unwrap().push("release".to_owned());
        self.outstanding.fetch_sub(1, Ordering::SeqCst);
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                Err(DomainError::Invariant("release failed".into()))
            } else {
                Ok(())
            }
        })
    }
}

impl MockPurgeGc {
    fn new() -> Self {
        Self::default()
    }

    fn reclaim(self, content_hash: ContentHash, outcome: Reclaim) -> Self {
        self.reclaim_script
            .lock()
            .unwrap()
            .insert(content_hash, outcome);
        self
    }

    fn reclaim_calls(&self) -> Vec<(Uuid, ContentHash)> {
        self.reclaim_calls.lock().unwrap().clone()
    }

    fn trace(&self) -> Vec<String> {
        self.trace.lock().unwrap().clone()
    }

    fn outstanding_leases(&self) -> usize {
        self.outstanding_leases.load(Ordering::SeqCst)
    }

    fn with_pending(self, pending: Vec<PendingPurge>) -> Self {
        *self.pending.lock().unwrap() = pending;
        self
    }

    fn with_refs(self, artifact_id: Uuid, refs: Vec<PurgedRef>) -> Self {
        self.refs.lock().unwrap().insert(artifact_id, refs);
        self
    }

    /// Script what the under-lock re-read answers for `artifact_id`.
    fn prepares(self, artifact_id: Uuid, outcome: PurgePreparation) -> Self {
        self.prepare_script
            .lock()
            .unwrap()
            .insert(artifact_id, outcome);
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

    /// Did the terminal transition run — `ArtifactPurged` appended and
    /// the work item ended? Distinct from [`Self::is_retired`], which
    /// is the `deleted_at` write the *preparation* performs: an aborted
    /// run leaves an artifact retired and not purged, and the whole
    /// safety argument for that order rests on telling the two apart.
    fn is_purged(&self, artifact_id: Uuid) -> bool {
        self.purged.lock().unwrap().contains(&artifact_id)
    }

    /// Did the preparation retire the row (`artifacts.deleted_at`)?
    fn is_retired(&self, artifact_id: Uuid) -> bool {
        self.retired.lock().unwrap().contains_key(&artifact_id)
    }

    /// The timestamp the preparation retired with, so a test can prove
    /// a retry re-asserts rather than rewrites it.
    fn retired_at(&self, artifact_id: Uuid) -> Option<DateTime<Utc>> {
        self.retired.lock().unwrap().get(&artifact_id).copied()
    }

    fn completed_batches(&self) -> Vec<AppendEvents> {
        self.completed_batches.lock().unwrap().clone()
    }

    /// The adapter corrects the worklist row under the lock on **both**
    /// keep paths; mirror that so a retry reads the same thing the use
    /// case just adopted, and so the terminal batch still agrees with
    /// the worklist it is validated against.
    fn refresh_worklist(&self, artifact_id: Uuid, content_hash: &ContentHash, refs: u32) {
        if let Some(item) = self
            .refs
            .lock()
            .unwrap()
            .get_mut(&artifact_id)
            .and_then(|v| v.iter_mut().find(|item| item.content_hash == *content_hash))
        {
            item.refs_remaining = refs;
        }
    }
}

impl PurgeGcPort for MockPurgeGc {
    fn list_pending_purge(
        &self,
        limit: u32,
        after_artifact_id: Option<Uuid>,
    ) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        let fail = self.list_err.load(Ordering::SeqCst);
        // Membership is the event rule — a work item with no
        // `ArtifactPurged` — and deliberately NOT `deleted_at`: the
        // adapter's query is declared `DELETED-INCLUSIVE` for exactly
        // this reason, and it is what lets an aborted run (retired, not
        // purged) be resumed by the next sweep.
        let purged = self.purged.lock().unwrap().clone();
        let mut rows: Vec<PendingPurge> = self
            .pending
            .lock()
            .unwrap()
            .iter()
            .filter(|item| !purged.contains(&item.artifact_id))
            .filter(|item| after_artifact_id.is_none_or(|a| item.artifact_id > a))
            .cloned()
            .collect();
        // The adapter's contract: ordered by `artifact_id`, so the
        // caller can hand the last one back as the next page's cursor.
        rows.sort_by_key(|item| item.artifact_id);
        rows.truncate(limit as usize);
        Box::pin(async move {
            if fail {
                Err(DomainError::Invariant("pending list failed".into()))
            } else {
                Ok(rows)
            }
        })
    }

    fn begin_blob_reclaim(
        &self,
        artifact_id: Uuid,
        content_hash: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<BlobReclaim>> {
        self.reclaim_calls
            .lock()
            .unwrap()
            .push((artifact_id, content_hash.clone()));
        self.trace.lock().unwrap().push("lease".to_owned());
        let scripted = self
            .reclaim_script
            .lock()
            .unwrap()
            .get(content_hash)
            .cloned()
            .unwrap_or(Reclaim::Granted);
        let outcome = match scripted {
            Reclaim::Granted | Reclaim::GrantedReleaseFails => {
                self.outstanding_leases.fetch_add(1, Ordering::SeqCst);
                Ok(BlobReclaim::Granted(Box::new(MockGuard {
                    trace: Arc::clone(&self.trace),
                    outstanding: Arc::clone(&self.outstanding_leases),
                    fail: matches!(scripted, Reclaim::GrantedReleaseFails),
                })))
            }
            Reclaim::Contended => Ok(BlobReclaim::Contended),
            Reclaim::Referenced(n) => {
                self.refresh_worklist(artifact_id, content_hash, n);
                Ok(BlobReclaim::Referenced { refs_now: n })
            }
            Reclaim::ProtectedClaim(n) => {
                self.refresh_worklist(artifact_id, content_hash, n);
                Ok(BlobReclaim::ProtectedClaim { claimants: n })
            }
            Reclaim::Err => Err(DomainError::Invariant("lease failed".into())),
        };
        Box::pin(async move { outcome })
    }

    fn purge_artifact_refs(
        &self,
        artifact_id: Uuid,
        retired_at: DateTime<Utc>,
    ) -> BoxFuture<'_, DomainResult<PurgePreparation>> {
        self.purge_calls.lock().unwrap().push(artifact_id);
        let fail = self.purge_err_for.lock().unwrap().contains(&artifact_id);
        let scripted = self
            .prepare_script
            .lock()
            .unwrap()
            .get(&artifact_id)
            .cloned();
        let refs = self
            .refs
            .lock()
            .unwrap()
            .get(&artifact_id)
            .cloned()
            .unwrap_or_default();
        let outcome = if fail {
            None
        } else {
            Some(scripted.unwrap_or(PurgePreparation::Prepared(refs)))
        };

        // The adapter retires the row in this transaction, on the
        // `Prepared` paths and only those — a refusal leaves the
        // artifact in service. `COALESCE` keeps the earlier timestamp,
        // so a retry re-asserts rather than rewrites. The retirement
        // also lands in the shared trace, which is the only way a test
        // can assert it precedes the storage delete.
        if matches!(outcome, Some(PurgePreparation::Prepared(_))) {
            self.retired
                .lock()
                .unwrap()
                .entry(artifact_id)
                .or_insert(retired_at);
            self.trace.lock().unwrap().push("retire".to_owned());
        }

        Box::pin(async move {
            match outcome {
                None => Err(DomainError::Invariant("prepare failed".into())),
                Some(outcome) => Ok(outcome),
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
            self.purged.lock().unwrap().insert(artifact_id);
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
    /// Shared with [`MockPurgeGc`] when a test needs the interleaving.
    trace: Mutex<Option<Arc<Mutex<Vec<String>>>>>,
}

impl MockStorage {
    fn new() -> Self {
        Self::default()
    }

    /// Record `delete` into the same ordered trace the lease/release
    /// pair writes to.
    fn tracing_into(self, trace: Arc<Mutex<Vec<String>>>) -> Self {
        *self.trace.lock().unwrap() = Some(trace);
        self
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
        if let Some(trace) = self.trace.lock().unwrap().as_ref() {
            trace.lock().unwrap().push("delete".to_owned());
        }
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

/// An unremarkable pending item — no tag, no delete, no quarantine —
/// so a test that is about something else does not restate the four
/// flags each time.
fn plain_pending(artifact_id: Uuid) -> PendingPurge {
    PendingPurge {
        artifact_id,
        quarantine_status: QuarantineStatus::None,
        tag_targeted: false,
        expired_only_by_keep_last_n: false,
        user_deleted: false,
    }
}

/// `n` distinct ids in ascending order — the keyset walk's order, so a
/// test can assert which ones a capped run reached.
fn sorted_ids(n: usize) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = (0..n).map(|_| Uuid::new_v4()).collect();
    ids.sort();
    ids
}

/// One artifact with two refcount-0 hashes whose **second** delete
/// fails once: the mid-sweep abort shape. The first blob is really
/// gone, the second is not, and the terminal transition never runs — so
/// the artifact ends the run with its bytes partly destroyed and its
/// work item still pending.
fn aborting_two_hash_harness(
    artifact_id: Uuid,
    first: &ContentHash,
    second: &ContentHash,
) -> Harness {
    build(
        MockPurgeGc::new()
            .with_pending(vec![plain_pending(artifact_id)])
            .with_refs(
                artifact_id,
                vec![work(first.clone(), 0), work(second.clone(), 0)],
            ),
        MockStorage::new()
            .with_present(first.clone())
            .with_present(second.clone())
            .fail_delete_once(second.clone()),
        MockReconcileGate::converged(),
    )
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
    assert!(h.gc.is_purged(artifact_id));
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
    assert!(h.gc.is_purged(artifact_id));
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
    let h = aborting_two_hash_harness(artifact_id, &first, &second);

    let first_run = h.uc.process_expired(ts(5000)).await.unwrap();
    assert_eq!(first_run.errors, 1);
    assert_eq!(first_run.purged_events, 0);
    assert_eq!(h.gc.complete_call_count(), 0);
    assert!(!h.gc.is_purged(artifact_id));
    assert!(purged_events(&h.gc).is_empty());

    let retry = h.uc.process_expired(ts(6000)).await.unwrap();
    assert_eq!(retry.errors, 0);
    assert_eq!(retry.purged_events, 2);
    assert!(h.gc.is_purged(artifact_id));
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
    assert!(h.gc.is_purged(artifact_id));
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
        assert!(!h.gc.is_purged(artifact_id));
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
    assert!(!h.gc.is_purged(bad));
    assert!(h.gc.is_purged(good));
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
    assert!(!h.gc.is_purged(artifact_id));

    let retry = h.uc.process_expired(ts(9300)).await.unwrap();
    assert_eq!(retry.errors, 0);
    assert_eq!(retry.purged_events, 1);
    assert!(h.gc.is_purged(artifact_id));
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
    assert!(!h.gc.is_purged(artifact_id));

    let retry = h.uc.process_expired(ts(9500)).await.unwrap();
    assert_eq!(retry.errors, 0);
    assert_eq!(retry.purged_events, 1);
    assert_eq!(h.storage.delete_attempts(), vec![content_hash]);
    assert!(h.gc.is_purged(artifact_id));
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
    assert!(!h.gc.is_purged(artifact_id));
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
    assert!(h.gc.is_purged(artifact_id));
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
    assert!(h.gc.is_purged(artifact_id));
}

// ===========================================================================
// The page is a snapshot: the re-read under the artifact lock decides
// ===========================================================================

/// The page row said the artifact was collectable; the read the
/// adapter takes under the artifact lock said it had become retained
/// evidence. The sweep has to take the second answer, count it apart
/// from the steady-state skip, and leave everything alone.
#[tokio::test]
async fn a_protection_refusal_under_the_lock_stops_the_artifact_and_is_counted_apart() {
    for status in [
        QuarantineStatus::Quarantined,
        QuarantineStatus::Rejected,
        QuarantineStatus::ScanIndeterminate,
    ] {
        let artifact_id = Uuid::new_v4();
        let content_hash = hash(HASH_PRIMARY);
        let h = build(
            MockPurgeGc::new()
                // Collectable on the page — the pre-exit cannot catch
                // this, which is the whole point of the fixture.
                .with_pending(vec![pending(artifact_id, false, true)])
                .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
                .prepares(artifact_id, PurgePreparation::Protected { status }),
            MockStorage::new().with_present(content_hash),
            MockReconcileGate::converged(),
        );

        let summary = h.uc.process_expired(ts(8100)).await.unwrap();

        assert_eq!(summary.artifacts_visited, 1, "{status}");
        assert_eq!(
            summary.skipped_protected_under_lock, 1,
            "{status}: the refusal came from the reader that decides"
        );
        assert_eq!(
            summary.skipped_protected, 0,
            "{status}: the page-row pre-exit saw nothing, and the two \
             readers are counted apart so this stays visible"
        );
        assert_eq!(summary.errors, 0, "{status}: a refusal is not an error");
        assert_eq!(summary.blobs_deleted, 0, "{status}");
        assert_eq!(summary.blobs_kept, 0, "{status}");
        assert_eq!(summary.purged_events, 0, "{status}");
        // The lock *was* taken — this is not the pre-exit — and
        // nothing past it ran.
        assert_eq!(h.gc.purge_call_count(), 1, "{status}");
        assert!(h.gc.reclaim_calls().is_empty(), "{status}");
        assert!(h.storage.delete_attempts().is_empty(), "{status}");
        assert_eq!(h.gc.complete_call_count(), 0, "{status}");
        assert!(!h.gc.is_purged(artifact_id), "{status}");
    }
}

/// The same shape for the other rule: a ref came to resolve to a
/// `KeepLastN`-expired artifact after its page row was read.
#[tokio::test]
async fn a_tag_exemption_under_the_lock_stops_the_artifact_and_is_counted_apart() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![pending(artifact_id, false, true)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
            .prepares(artifact_id, PurgePreparation::TagExempt),
        MockStorage::new().with_present(content_hash),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(8200)).await.unwrap();

    assert_eq!(summary.skipped_tag_exempt_under_lock, 1);
    assert_eq!(
        summary.skipped_tag_exempt, 0,
        "the page row carried no ref; the two readers are counted apart"
    );
    assert_eq!(summary.errors, 0);
    assert_eq!(summary.purged_events, 0);
    assert_eq!(h.gc.purge_call_count(), 1);
    assert!(h.storage.delete_attempts().is_empty());
    assert!(!h.gc.is_purged(artifact_id));
}

/// `NoArtifact` is neither of the refusals and neither is it an error:
/// the row the page offered is gone, so there are no bytes left to
/// release through it. It must not land in a protection counter — an
/// operator reading `skipped_protected_under_lock` is reading "a
/// protection held", and a vanished row is not that.
#[tokio::test]
async fn a_vanished_artifact_row_is_not_a_protection_refusal() {
    let artifact_id = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![plain_pending(artifact_id)])
            .prepares(artifact_id, PurgePreparation::NoArtifact),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(8300)).await.unwrap();

    assert_eq!(summary.artifacts_visited, 1);
    assert_eq!(summary.skipped_protected_under_lock, 0);
    assert_eq!(summary.skipped_tag_exempt_under_lock, 0);
    assert_eq!(summary.skipped_protected, 0);
    assert_eq!(summary.skipped_tag_exempt, 0);
    assert_eq!(summary.errors, 0);
    assert_eq!(summary.purged_events, 0);
    assert_eq!(h.gc.complete_call_count(), 0);
}

/// The counter-test: a `Prepared` answer from the same reader purges
/// normally, with every skip counter still at zero. Without it, a
/// re-read that refused everything would satisfy the three tests above.
#[tokio::test]
async fn an_artifact_the_fresh_read_still_clears_is_purged_normally() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![pending(artifact_id, false, true)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)]),
        MockStorage::new().with_present(content_hash.clone()),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(8400)).await.unwrap();

    assert_eq!(summary.blobs_deleted, 1);
    assert_eq!(summary.purged_events, 1);
    assert_eq!(summary.skipped_protected_under_lock, 0);
    assert_eq!(summary.skipped_tag_exempt_under_lock, 0);
    assert_eq!(summary.skipped_protected, 0);
    assert_eq!(summary.skipped_tag_exempt, 0);
    assert_eq!(h.storage.delete_attempts(), vec![content_hash]);
    assert!(h.gc.is_purged(artifact_id));
}

/// A refusal is per-artifact: the sweep keeps walking the page and
/// collects the artifacts behind it. (The real hazard runs the other
/// way round — the items *ahead* of an artifact are what make its
/// window long — but a refusal that aborted the page would starve
/// everything behind a single tagged artifact.)
#[tokio::test]
async fn a_refusal_does_not_stop_the_rest_of_the_page() {
    let ids = sorted_ids(2);
    let (refused, collected) = (ids[0], ids[1]);
    let content_hash = hash(HASH_PRIMARY);
    let other_hash = hash(HASH_META);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![
                pending(refused, false, true),
                pending(collected, false, true),
            ])
            .with_refs(refused, vec![work(content_hash, 0)])
            .with_refs(collected, vec![work(other_hash.clone(), 0)])
            .prepares(refused, PurgePreparation::TagExempt),
        MockStorage::new().with_present(other_hash.clone()),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(8500)).await.unwrap();

    assert_eq!(summary.artifacts_visited, 2);
    assert_eq!(summary.skipped_tag_exempt_under_lock, 1);
    assert_eq!(summary.blobs_deleted, 1);
    assert_eq!(h.storage.delete_attempts(), vec![other_hash]);
    assert!(!h.gc.is_purged(refused));
    assert!(h.gc.is_purged(collected));
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
    assert!(h.gc.is_purged(artifact_id));
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
    assert!(h.gc.is_purged(artifact_id));
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
    assert!(h.gc.is_purged(artifact_id));
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
        assert!(!h.gc.is_purged(artifact_id));
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

// ---------------------------------------------------------------------------
// The blob-reclamation lease: the lock the destructive step happens under
// ---------------------------------------------------------------------------

/// The ordering the whole fix rests on: the lease is taken, the bytes
/// are deleted **while it is held**, and only then is it released. A
/// delete outside the lease is the bug this unit exists to remove — the
/// count and the act would again be two unrelated moments.
#[tokio::test]
async fn the_delete_happens_between_taking_the_lease_and_releasing_it() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let gc = MockPurgeGc::new()
        .with_pending(vec![plain_pending(artifact_id)])
        .with_refs(artifact_id, vec![work(content_hash.clone(), 0)]);
    let trace = Arc::clone(&gc.trace);
    let h = build(
        gc,
        MockStorage::new()
            .with_present(content_hash.clone())
            .tracing_into(trace),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.blobs_deleted, 1);
    assert_eq!(
        h.gc.trace(),
        vec![
            "retire".to_owned(),
            "lease".to_owned(),
            "delete".to_owned(),
            "release".to_owned()
        ],
        "the delete must be inside the lease, not before or after it — \
         and the retirement ahead of all three"
    );
    assert_eq!(h.gc.reclaim_calls(), vec![(artifact_id, content_hash)]);
    assert_eq!(
        h.gc.outstanding_leases(),
        0,
        "the lease must not outlive the sweep"
    );
}

/// A blob a live reference already keeps never reaches the lease at
/// all: there is nothing to authorise, because nothing is going to be
/// deleted. Pins that the lock is taken on the destructive path only —
/// a sweep that leased every hash it walked would contend with every
/// ingest for no reason.
#[tokio::test]
async fn a_blob_with_live_references_is_never_leased() {
    let artifact_id = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![plain_pending(artifact_id)])
            .with_refs(artifact_id, vec![work(hash(HASH_PRIMARY), 3)]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.blobs_kept, 1);
    assert!(h.gc.reclaim_calls().is_empty());
    // The retirement is the preparation's, not the lease's: it happens
    // on every collected artifact, including one whose bytes a live
    // reference keeps.
    assert_eq!(h.gc.trace(), vec!["retire".to_owned()]);
}

/// Contention is a deferral, not a failure and not a delete: nothing is
/// removed, no terminal event is emitted, the artifact stays pending,
/// and the summary says so in a field an operator can watch.
#[tokio::test]
async fn a_contended_lease_defers_the_blob_and_leaves_the_work_standing() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![plain_pending(artifact_id)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
            .reclaim(content_hash.clone(), Reclaim::Contended),
        MockStorage::new().with_present(content_hash),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.blobs_deferred, 1);
    assert_eq!(summary.blobs_deleted, 0);
    assert_eq!(summary.purged_events, 0);
    assert_eq!(
        summary.errors, 0,
        "a deferral is the mechanism working, not an error"
    );
    assert!(h.storage.delete_attempts().is_empty());
    assert!(!h.gc.is_purged(artifact_id));
    assert_eq!(h.gc.complete_call_count(), 0);
}

/// …and the next run picks it up from the retained worklist. This is
/// the retry half of "skip when in doubt": a deferred blob is not a
/// lost one.
#[tokio::test]
async fn a_deferred_blob_is_retried_by_the_next_run() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![plain_pending(artifact_id)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
            .reclaim(content_hash.clone(), Reclaim::Contended),
        MockStorage::new().with_present(content_hash.clone()),
        MockReconcileGate::converged(),
    );

    assert_eq!(
        h.uc.process_expired(ts(2000)).await.unwrap().blobs_deferred,
        1
    );

    // The lock frees; the same durable worklist is walked again.
    h.gc.reclaim_script.lock().unwrap().remove(&content_hash);
    let second = h.uc.process_expired(ts(3000)).await.unwrap();
    assert_eq!(second.blobs_deleted, 1);
    assert_eq!(second.purged_events, 1);
    assert_eq!(h.storage.delete_attempts(), vec![content_hash]);
    assert!(h.gc.is_purged(artifact_id));
}

/// The worklist's zero was a snapshot, and under the lock it turns out
/// to be stale: the bytes are claimed again. The blob stays, the purge
/// still finishes (re-asking forever would leave the artifact
/// permanently unfinishable), and the terminal event states the count
/// that actually held rather than the zero that no longer did.
#[tokio::test]
async fn a_recount_that_is_no_longer_zero_keeps_the_blob_and_states_the_count() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![plain_pending(artifact_id)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
            .reclaim(content_hash.clone(), Reclaim::Referenced(2)),
        MockStorage::new().with_present(content_hash),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.blobs_deleted, 0);
    assert_eq!(summary.blobs_kept, 1);
    assert_eq!(summary.blobs_deferred, 0);
    assert_eq!(summary.purged_events, 1);
    assert!(
        h.storage.delete_attempts().is_empty(),
        "bytes something references must not be deleted"
    );
    assert!(h.gc.is_purged(artifact_id));
    assert_eq!(purged_events(&h.gc)[0].refs_remaining, 2);
}

/// The refcount was genuinely zero and the bytes are still claimed:
/// retained scan evidence holds this hash with no reference edge to
/// count, because the refcount repair deliberately mints none for a
/// protected artifact. The blob stays, the sibling's purge still
/// finishes (a `rejected` artifact is permanent, so re-asking would
/// never get a different answer), and the terminal event carries the
/// claim count — `refs_remaining > 0` is what makes "the blob stays"
/// readable from the stream.
#[tokio::test]
async fn a_protected_claim_on_the_shared_bytes_keeps_the_blob_and_states_the_count() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![plain_pending(artifact_id)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
            .reclaim(content_hash.clone(), Reclaim::ProtectedClaim(1)),
        MockStorage::new().with_present(content_hash),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.blobs_deleted, 0);
    assert_eq!(summary.blobs_kept, 1);
    assert_eq!(
        summary.blobs_deferred, 0,
        "a protected claim is a keep, not a deferral — re-asking would          never finish the sibling's purge"
    );
    assert_eq!(summary.purged_events, 1);
    assert!(
        h.storage.delete_attempts().is_empty(),
        "bytes retained evidence claims must not be deleted"
    );
    assert!(h.gc.is_purged(artifact_id));
    assert_eq!(purged_events(&h.gc)[0].refs_remaining, 1);
}

/// A lease that cannot be taken at all (port/infra failure) is an
/// error, and errors do not delete.
#[tokio::test]
async fn a_failing_lease_deletes_nothing_and_is_counted_as_an_error() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![plain_pending(artifact_id)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
            .reclaim(content_hash.clone(), Reclaim::Err),
        MockStorage::new().with_present(content_hash),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.errors, 1);
    assert_eq!(summary.blobs_deleted, 0);
    assert_eq!(summary.blobs_deferred, 0);
    assert!(h.storage.delete_attempts().is_empty());
    assert!(!h.gc.is_purged(artifact_id));
}

/// The release is best-effort reporting, not part of the decision: the
/// bytes are already gone by the time it runs, and the lock ends with
/// the transaction whether or not the release statement succeeds.
/// Treating the failure as a storage error would strand a completed
/// delete behind a `StorageError` retry forever.
#[tokio::test]
async fn a_release_failure_does_not_undo_a_completed_delete() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![plain_pending(artifact_id)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
            .reclaim(content_hash.clone(), Reclaim::GrantedReleaseFails),
        MockStorage::new().with_present(content_hash.clone()),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.blobs_deleted, 1);
    assert_eq!(summary.errors, 0);
    assert_eq!(summary.purged_events, 1);
    assert_eq!(h.storage.delete_attempts(), vec![content_hash]);
    assert!(h.gc.is_purged(artifact_id));
}

/// A storage failure inside a granted lease still releases it. Without
/// this the failure path would hold a pooled connection's transaction —
/// and the hash lock with it — for as long as the error path took, and
/// every ingest touching those bytes would queue behind a sweep that
/// had already given up.
#[tokio::test]
async fn a_storage_failure_inside_the_lease_still_releases_it() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let gc = MockPurgeGc::new()
        .with_pending(vec![plain_pending(artifact_id)])
        .with_refs(artifact_id, vec![work(content_hash.clone(), 0)]);
    let trace = Arc::clone(&gc.trace);
    let h = build(
        gc,
        MockStorage::new()
            .with_present(content_hash.clone())
            .fail_delete_once(content_hash)
            .tracing_into(trace),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.errors, 1);
    assert_eq!(summary.purged_events, 0);
    assert_eq!(
        h.gc.trace(),
        vec![
            "retire".to_owned(),
            "lease".to_owned(),
            "delete".to_owned(),
            "release".to_owned()
        ]
    );
    assert_eq!(h.gc.outstanding_leases(), 0);
}

// ---------------------------------------------------------------------------
// The retirement leads the destruction
// ---------------------------------------------------------------------------

/// The ordering this unit exists for: `artifacts.deleted_at` is durable
/// before the first byte is destroyed, not after the last. Asserted on
/// the shared trace, because the only way to be wrong about this is to
/// have the two writes in the wrong order, and a trace is the only
/// thing that can see an order.
#[tokio::test]
async fn the_retirement_lands_before_the_first_storage_delete() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let gc = MockPurgeGc::new()
        .with_pending(vec![plain_pending(artifact_id)])
        .with_refs(artifact_id, vec![work(content_hash.clone(), 0)]);
    let trace = Arc::clone(&gc.trace);
    let h = build(
        gc,
        MockStorage::new()
            .with_present(content_hash)
            .tracing_into(trace),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.blobs_deleted, 1);
    assert_eq!(summary.purged_events, 1);
    let trace = h.gc.trace();
    assert_eq!(
        trace.iter().position(|step| step == "retire"),
        Some(0),
        "the retirement is the first thing the sweep does to this artifact: {trace:?}"
    );
    assert!(
        trace.iter().position(|step| step == "delete").unwrap()
            > trace.iter().position(|step| step == "retire").unwrap(),
        "a delete ahead of the retirement is the defect: {trace:?}"
    );
    // The retirement carries the sweep's injected clock, so a retry is
    // coherent with the `ArtifactPurged` it eventually emits.
    assert_eq!(h.gc.retired_at(artifact_id), Some(ts(2000)));
    assert!(h.gc.is_purged(artifact_id));
}

/// The load-bearing safety claim for the order above: an aborted run
/// leaves a **retired artifact with intact bytes**, and the next sweep
/// finishes it with no operator step.
///
/// The abort is driven by failing the second hash's storage delete
/// once, so the first blob is genuinely gone when the run ends — the
/// exact state the old order served a `500` from. The resume works
/// because work-item membership is the event rule and never
/// `deleted_at`: `list_pending_purge` offers the retired artifact
/// again, and the second sweep terminates it.
#[tokio::test]
async fn an_aborted_run_leaves_the_artifact_retired_and_the_next_sweep_finishes_it() {
    let artifact_id = Uuid::new_v4();
    let first = hash(HASH_PRIMARY);
    let second = hash(HASH_CHILD);
    let h = aborting_two_hash_harness(artifact_id, &first, &second);

    let aborted = h.uc.process_expired(ts(5000)).await.unwrap();
    assert_eq!(aborted.errors, 1);
    assert_eq!(aborted.purged_events, 0);
    assert_eq!(
        h.storage.delete_attempts(),
        vec![first.clone(), second.clone()]
    );
    assert!(
        h.gc.is_retired(artifact_id),
        "the first blob is gone, so the row must already be out of service"
    );
    assert!(
        !h.gc.is_purged(artifact_id),
        "the work item is not terminated — that is what makes the resume possible"
    );

    // The retired artifact is still the work set. This is the whole
    // reason retiring early is safe, so it is asserted on the port and
    // not inferred from the sweep succeeding.
    let still_pending = h.gc.list_pending_purge(10, None).await.unwrap();
    assert_eq!(
        still_pending
            .iter()
            .map(|item| item.artifact_id)
            .collect::<Vec<_>>(),
        vec![artifact_id]
    );

    let resumed = h.uc.process_expired(ts(6000)).await.unwrap();
    assert_eq!(resumed.errors, 0);
    assert_eq!(resumed.artifacts_visited, 1);
    assert_eq!(resumed.purged_events, 2);
    assert!(h.gc.is_purged(artifact_id));
    // The second sweep re-asserts the retirement rather than rewriting
    // it: the moment the artifact left service is an audit fact, and
    // the adapter's `COALESCE` keeps the earlier timestamp.
    assert_eq!(h.gc.retired_at(artifact_id), Some(ts(5000)));
    assert!(h.gc.list_pending_purge(10, None).await.unwrap().is_empty());
}

/// A deferral is the other aborted shape, and it reaches the same
/// state: the artifact is retired by the preparation, nothing was
/// deleted, no terminal event was emitted, and the work stands. Pins
/// that `blobs_deferred` is unchanged by the new order.
#[tokio::test]
async fn a_deferred_blob_leaves_a_retired_artifact_with_its_bytes_intact() {
    let artifact_id = Uuid::new_v4();
    let content_hash = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![plain_pending(artifact_id)])
            .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
            .reclaim(content_hash.clone(), Reclaim::Contended),
        MockStorage::new().with_present(content_hash),
        MockReconcileGate::converged(),
    );

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.blobs_deferred, 1);
    assert_eq!(summary.blobs_deleted, 0);
    assert_eq!(summary.purged_events, 0);
    assert!(h.storage.delete_attempts().is_empty());
    assert!(h.gc.is_retired(artifact_id));
    assert!(!h.gc.is_purged(artifact_id));
    assert_eq!(h.gc.list_pending_purge(10, None).await.unwrap().len(), 1);
}

/// A blob kept because something still claims it is not a declined
/// purge: the artifact's retention decision stands, so it retires and
/// its work item terminates. Only the *bytes* survive. Both keep
/// outcomes are covered because they are reached by different
/// questions (a live refcount, a claim the refcount cannot show).
#[tokio::test]
async fn a_kept_blob_still_retires_and_terminates_the_artifact() {
    for keep in [Reclaim::Referenced(2), Reclaim::ProtectedClaim(1)] {
        let artifact_id = Uuid::new_v4();
        let content_hash = hash(HASH_PRIMARY);
        let h = build(
            MockPurgeGc::new()
                .with_pending(vec![plain_pending(artifact_id)])
                .with_refs(artifact_id, vec![work(content_hash.clone(), 0)])
                .reclaim(content_hash.clone(), keep.clone()),
            MockStorage::new().with_present(content_hash),
            MockReconcileGate::converged(),
        );

        let summary = h.uc.process_expired(ts(2000)).await.unwrap();
        assert_eq!(summary.blobs_kept, 1, "{keep:?}");
        assert_eq!(summary.blobs_deleted, 0, "{keep:?}");
        assert!(h.storage.delete_attempts().is_empty(), "{keep:?}");
        assert!(h.gc.is_retired(artifact_id), "{keep:?}");
        assert!(h.gc.is_purged(artifact_id), "{keep:?}");
    }
}

/// **A purge that declines to act retires nothing.** This is the guard
/// on the new order: `deleted_at` is the artifact's exit from service,
/// so writing it earlier must not let a *refusal* — a protection
/// holding, a tag landing, a row vanishing, a failing preparation —
/// take an artifact out of service as a side effect of being
/// considered.
///
/// Every refusal the sweep can reach is covered: the two page-row
/// pre-exits, the three under-lock outcomes, and the preparation error.
#[tokio::test]
async fn no_refusal_retires_the_artifact() {
    // The two page-row pre-exits: refused before the port is called at
    // all, so there is nothing to script.
    let evidence = Uuid::new_v4();
    let tagged = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new().with_pending(vec![
            PendingPurge {
                artifact_id: evidence,
                quarantine_status: QuarantineStatus::Quarantined,
                tag_targeted: false,
                expired_only_by_keep_last_n: false,
                user_deleted: false,
            },
            pending(tagged, true, true),
        ]),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );
    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.skipped_protected, 1);
    assert_eq!(summary.skipped_tag_exempt, 1);
    assert_eq!(h.gc.purge_call_count(), 0);
    assert!(!h.gc.is_retired(evidence));
    assert!(!h.gc.is_retired(tagged));

    // The three under-lock outcomes, plus a preparation that fails
    // outright: the port was called, and none of them may retire.
    let refusals = [
        PurgePreparation::Protected {
            status: QuarantineStatus::Rejected,
        },
        PurgePreparation::TagExempt,
        PurgePreparation::NoArtifact,
    ];
    for refusal in refusals {
        let artifact_id = Uuid::new_v4();
        let h = build(
            MockPurgeGc::new()
                .with_pending(vec![plain_pending(artifact_id)])
                .with_refs(artifact_id, vec![work(hash(HASH_PRIMARY), 0)])
                .prepares(artifact_id, refusal.clone()),
            MockStorage::new().with_present(hash(HASH_PRIMARY)),
            MockReconcileGate::converged(),
        );
        h.uc.process_expired(ts(2000)).await.unwrap();
        assert_eq!(h.gc.purge_call_count(), 1, "{refusal:?}");
        assert!(h.storage.delete_attempts().is_empty(), "{refusal:?}");
        assert!(!h.gc.is_retired(artifact_id), "{refusal:?}");
        assert!(!h.gc.is_purged(artifact_id), "{refusal:?}");
    }

    let failing = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![plain_pending(failing)])
            .with_refs(failing, vec![work(hash(HASH_PRIMARY), 0)])
            .fail_purge_for(failing),
        MockStorage::new().with_present(hash(HASH_PRIMARY)),
        MockReconcileGate::converged(),
    );
    assert_eq!(h.uc.process_expired(ts(2000)).await.unwrap().errors, 1);
    assert!(!h.gc.is_retired(failing));
}

// ---------------------------------------------------------------------------
// The capped, paged walk
// ---------------------------------------------------------------------------

/// The walk pages by keyset and the cursor advances over rows it did
/// not act on, so a full page is followed by the next one rather than
/// by the same one again.
#[tokio::test]
async fn the_walk_pages_by_keyset_until_the_set_is_exhausted() {
    let ids = sorted_ids(5);
    let gc = MockPurgeGc::new().with_pending(ids.iter().copied().map(plain_pending).collect());
    let mut h = build(gc, MockStorage::new(), MockReconcileGate::converged());
    h.uc.batch_size = 2;

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.artifacts_visited, 5);
    // 2 + 2 + 1: the short page ends the walk without a further probe.
    assert_eq!(h.gc.list_call_count(), 3);
    assert_eq!(h.gc.purge_calls.lock().unwrap().clone(), ids);
}

/// One run examines at most `max_batches_per_tick * batch_size`
/// artifacts. The first sweep after a deployment faces the whole
/// accumulated backlog, and "load it all and find out how big it was"
/// is exactly what a destructive sweep may not do.
#[tokio::test]
async fn one_run_stops_at_the_per_tick_cap_and_leaves_the_rest() {
    let ids = sorted_ids(9);
    let gc = MockPurgeGc::new().with_pending(ids.iter().copied().map(plain_pending).collect());
    let mut h = build(gc, MockStorage::new(), MockReconcileGate::converged());
    h.uc.batch_size = 2;
    h.uc.max_batches_per_tick = 3;

    let summary = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(summary.artifacts_visited, 6, "3 pages of 2");
    assert_eq!(h.gc.list_call_count(), 3);
    assert_eq!(h.gc.purge_calls.lock().unwrap().clone(), ids[..6].to_vec());

    // The remainder is the next run's work: nothing was skipped, only
    // deferred, and the set is consumed as artifacts retire.
    h.gc.purge_calls.lock().unwrap().clear();
    let second = h.uc.process_expired(ts(3000)).await.unwrap();
    assert_eq!(second.artifacts_visited, 6);
    assert_eq!(h.gc.purge_calls.lock().unwrap().clone(), ids[..6].to_vec());
}

/// The defaults are the design, pinned: a silent drift to a larger cap
/// re-opens the unbounded first run the cap exists to close, and the
/// numbers are deliberately retention-evaluate's rather than a second
/// idiom.
#[test]
fn the_page_cap_defaults_mirror_retention_evaluate() {
    assert_eq!(BATCH_SIZE, 1000, "design pin: BATCH_SIZE = 1000");
    assert_eq!(
        MAX_BATCHES_PER_TICK, 64,
        "design pin: MAX_BATCHES_PER_TICK = 64"
    );
    let uc = PurgeUseCase::new(
        Arc::new(MockPurgeGc::new()),
        Arc::new(MockStorage::new()),
        MockReconcileGate::converged(),
    );
    assert_eq!(uc.batch_size, BATCH_SIZE);
    assert_eq!(uc.max_batches_per_tick, MAX_BATCHES_PER_TICK);
}
