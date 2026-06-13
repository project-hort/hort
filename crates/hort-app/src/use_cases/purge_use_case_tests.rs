//! `PurgeUseCase::process_expired` unit tests.
//!
//! `hort-app` is the 100%-coverage tier (mock every port). Every branch
//! is pinned here:
//! - **reconcile-not-converged start-gate** → the sweep refuses to run
//!   (`AppError::Domain`), touches no port, emits no event.
//! - **refcount==0** → CAS blob deleted + `ArtifactPurged{refs_remaining=0}`.
//! - **refcount>0** → blob retained + `ArtifactPurged{refs_remaining=N}`.
//! - **metadata_blob walked alongside primary_content** (two
//!   `PurgedRef`s, one decision each).
//! - **two-stage idempotency**: a transient `StoragePort::delete`
//!   failure does NOT lose the `ArtifactExpired` (no `ArtifactPurged`
//!   appended), the sweep continues, the next sweep retries.
//! - **idempotent re-purge** on an already-absent blob is a clean
//!   no-op success (`delete` NotFound == gone).
//! - **evidence protection**: a quarantined/rejected/indeterminate pending
//!   artifact is skipped, never purged (defence-in-depth re-assertion).
//! - a `DebuggingRecorder` assertion that
//!   `hort_retention_purged_total{result=…}` fires with the documented
//!   `result` label values.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{ArtifactPurged, DomainEvent};
use hort_domain::ports::purge_gc::{PendingPurge, PurgeGcPort, PurgedRef};
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::BoxFuture;
use hort_domain::types::{ByteRange, ContentHash};

use crate::event_store_publisher::wrap_for_test;
use crate::use_cases::purge_use_case::{PurgeUseCase, RefcountReconcileGate};
use crate::use_cases::test_support::MockEventStore;

const HASH_PRIMARY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const HASH_META: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

fn hash(s: &str) -> ContentHash {
    s.parse().unwrap()
}

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).unwrap()
}

// ---------------------------------------------------------------------------
// MockReconcileGate
// ---------------------------------------------------------------------------

struct MockReconcileGate {
    converged: bool,
}
impl MockReconcileGate {
    fn converged() -> Arc<Self> {
        Arc::new(Self { converged: true })
    }
    fn not_converged() -> Arc<Self> {
        Arc::new(Self { converged: false })
    }
}
impl RefcountReconcileGate for MockReconcileGate {
    fn is_converged(&self) -> bool {
        self.converged
    }
}

// ---------------------------------------------------------------------------
// MockPurgeGc
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockPurgeGc {
    pending: Mutex<Vec<PendingPurge>>,
    /// `artifact_id -> PurgedRef list` the transactional step returns.
    refs: Mutex<std::collections::HashMap<Uuid, Vec<PurgedRef>>>,
    list_err: AtomicBool,
    purge_err_for: Mutex<Vec<Uuid>>,
    /// Every `purge_artifact_refs` call, in order (idempotency proof).
    purge_calls: Mutex<Vec<Uuid>>,
    list_calls: AtomicUsize,
}

impl MockPurgeGc {
    fn new() -> Self {
        Self::default()
    }
    fn with_pending(self, p: Vec<PendingPurge>) -> Self {
        *self.pending.lock().unwrap() = p;
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
    fn fail_purge_for(self, id: Uuid) -> Self {
        self.purge_err_for.lock().unwrap().push(id);
        self
    }
    fn purge_call_count(&self) -> usize {
        self.purge_calls.lock().unwrap().len()
    }
    fn list_call_count(&self) -> usize {
        self.list_calls.load(Ordering::SeqCst)
    }
}

impl PurgeGcPort for MockPurgeGc {
    fn list_pending_purge(&self) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        let err = self.list_err.load(Ordering::SeqCst);
        let p = self.pending.lock().unwrap().clone();
        Box::pin(async move {
            if err {
                Err(DomainError::Invariant("pending list failed".into()))
            } else {
                Ok(p)
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
                Err(DomainError::Invariant(
                    "purge_artifact_refs tx failed".into(),
                ))
            } else {
                Ok(refs)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// MockStorage — dedicated (the shared MockStoragePort lacks a transient
// non-NotFound delete-failure injection; a destructive item needs to
// distinguish "absent (NotFound, idempotent ok)" from "transient
// failure (must retry)"). Self-contained so test_support stays untouched.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockStorage {
    present: Mutex<Vec<ContentHash>>,
    /// Hashes whose `delete` returns a transient (non-NotFound) error.
    transient_fail: Mutex<Vec<ContentHash>>,
    deleted: Mutex<Vec<ContentHash>>,
}
impl MockStorage {
    fn new() -> Self {
        Self::default()
    }
    fn with_present(self, h: ContentHash) -> Self {
        self.present.lock().unwrap().push(h);
        self
    }
    fn fail_delete_transient(self, h: ContentHash) -> Self {
        self.transient_fail.lock().unwrap().push(h);
        self
    }
    fn deleted_hashes(&self) -> Vec<ContentHash> {
        self.deleted.lock().unwrap().clone()
    }
}
impl StoragePort for MockStorage {
    fn put(
        &self,
        _s: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<hort_domain::ports::storage::PutResult>> {
        Box::pin(async { unreachable!("purge never puts") })
    }
    fn get(
        &self,
        _h: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Box<dyn tokio::io::AsyncRead + Send + Unpin>>> {
        Box::pin(async { unreachable!("purge never gets") })
    }
    fn get_range(
        &self,
        _h: &ContentHash,
        _r: ByteRange,
    ) -> BoxFuture<'_, DomainResult<Box<dyn tokio::io::AsyncRead + Send + Unpin>>> {
        Box::pin(async { unreachable!("purge never range-gets") })
    }
    fn exists(&self, h: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
        let present = self.present.lock().unwrap().contains(h);
        Box::pin(async move { Ok(present) })
    }
    fn delete(&self, h: &ContentHash) -> BoxFuture<'_, DomainResult<()>> {
        self.deleted.lock().unwrap().push(h.clone());
        let transient = self.transient_fail.lock().unwrap().contains(h);
        let present = {
            let mut p = self.present.lock().unwrap();
            if let Some(i) = p.iter().position(|x| x == h) {
                p.remove(i);
                true
            } else {
                false
            }
        };
        let id = h.to_string();
        Box::pin(async move {
            if transient {
                // Transient backend error (e.g. S3 5xx) — NOT NotFound.
                Err(DomainError::Invariant(format!(
                    "transient delete failure: {id}"
                )))
            } else if present {
                Ok(())
            } else {
                // Already absent — adapter surfaces NotFound (allowed by
                // the StoragePort contract; the use case treats it as
                // the success-on-missing path).
                Err(DomainError::NotFound {
                    entity: "content",
                    id,
                })
            }
        })
    }
    fn size_of(&self, h: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
        let id = h.to_string();
        Box::pin(async move {
            Err(DomainError::NotFound {
                entity: "content",
                id,
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    uc: PurgeUseCase,
    gc: Arc<MockPurgeGc>,
    storage: Arc<MockStorage>,
    store: Arc<MockEventStore>,
}

fn build(gc: MockPurgeGc, storage: MockStorage, gate: Arc<MockReconcileGate>) -> Harness {
    let gc = Arc::new(gc);
    let storage = Arc::new(storage);
    let store = Arc::new(MockEventStore::new());
    let publisher = wrap_for_test(store.clone());
    let uc = PurgeUseCase::new(gc.clone(), storage.clone(), publisher, gate);
    Harness {
        uc,
        gc,
        storage,
        store,
    }
}

fn purged_events(store: &MockEventStore) -> Vec<ArtifactPurged> {
    store
        .appended_batches()
        .into_iter()
        .flat_map(|b| b.events)
        .filter_map(|e| match e.event {
            DomainEvent::ArtifactPurged(p) => Some(p),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// reconcile-converged start-gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refuses_to_run_when_reconcile_not_converged() {
    let aid = Uuid::new_v4();
    let h = build(
        MockPurgeGc::new().with_pending(vec![PendingPurge {
            artifact_id: aid,
            quarantine_status: QuarantineStatus::None,
        }]),
        MockStorage::new(),
        MockReconcileGate::not_converged(),
    );

    let err = h.uc.process_expired(ts(1000)).await.unwrap_err();
    assert!(matches!(err, crate::error::AppError::Domain(_)));
    assert!(err.to_string().contains("has not converged"), "got: {err}");

    // The gate fires BEFORE any port is touched and BEFORE any event.
    assert_eq!(h.gc.list_call_count(), 0, "must not even list pending");
    assert_eq!(h.gc.purge_call_count(), 0);
    assert!(h.storage.deleted_hashes().is_empty());
    assert!(purged_events(&h.store).is_empty());
}

#[tokio::test]
async fn runs_when_b35_converged_empty_pending_is_noop() {
    let h = build(
        MockPurgeGc::new(),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );
    let s = h.uc.process_expired(ts(1000)).await.unwrap();
    assert_eq!(s.artifacts_visited, 0);
    assert_eq!(s.purged_events, 0);
    assert_eq!(h.gc.list_call_count(), 1);
    assert!(purged_events(&h.store).is_empty());
}

// ---------------------------------------------------------------------------
// refcount == 0  → blob deleted + ArtifactPurged{refs_remaining=0}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refcount0_deletes_blob_and_emits_purged() {
    let aid = Uuid::new_v4();
    let ph = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id: aid,
                quarantine_status: QuarantineStatus::None,
            }])
            .with_refs(
                aid,
                vec![PurgedRef {
                    content_hash: ph.clone(),
                    refs_remaining: 0,
                }],
            ),
        MockStorage::new().with_present(ph.clone()),
        MockReconcileGate::converged(),
    );

    let s = h.uc.process_expired(ts(2000)).await.unwrap();
    assert_eq!(s.artifacts_visited, 1);
    assert_eq!(s.blobs_deleted, 1);
    assert_eq!(s.blobs_kept, 0);
    assert_eq!(s.purged_events, 1);
    assert_eq!(s.errors, 0);

    assert_eq!(h.storage.deleted_hashes(), vec![ph.clone()]);
    let evs = purged_events(&h.store);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact_id, aid);
    assert_eq!(evs[0].content_hash, ph);
    assert_eq!(evs[0].refs_remaining, 0);
    assert_eq!(evs[0].purged_at, ts(2000));
}

// ---------------------------------------------------------------------------
// refcount > 0  → blob retained + ArtifactPurged{refs_remaining=N}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refcount_gt0_retains_blob_and_records_refs_remaining() {
    let aid = Uuid::new_v4();
    let ph = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id: aid,
                quarantine_status: QuarantineStatus::Released,
            }])
            .with_refs(
                aid,
                vec![PurgedRef {
                    content_hash: ph.clone(),
                    refs_remaining: 3,
                }],
            ),
        // Blob present but MUST NOT be deleted (a live ref remains).
        MockStorage::new().with_present(ph.clone()),
        MockReconcileGate::converged(),
    );

    let s = h.uc.process_expired(ts(3000)).await.unwrap();
    assert_eq!(s.blobs_deleted, 0);
    assert_eq!(s.blobs_kept, 1);
    assert_eq!(s.purged_events, 1);
    assert!(
        h.storage.deleted_hashes().is_empty(),
        "a blob with refs_remaining>0 must NEVER be deleted"
    );
    let evs = purged_events(&h.store);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].refs_remaining, 3);
}

// ---------------------------------------------------------------------------
// metadata_blob walked alongside primary_content
// ---------------------------------------------------------------------------

#[tokio::test]
async fn walks_primary_and_metadata_blob_together() {
    let aid = Uuid::new_v4();
    let ph = hash(HASH_PRIMARY);
    let mh = hash(HASH_META);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id: aid,
                quarantine_status: QuarantineStatus::None,
            }])
            .with_refs(
                aid,
                vec![
                    PurgedRef {
                        content_hash: ph.clone(),
                        refs_remaining: 0,
                    },
                    // metadata blob still referenced by another artifact.
                    PurgedRef {
                        content_hash: mh.clone(),
                        refs_remaining: 1,
                    },
                ],
            ),
        MockStorage::new()
            .with_present(ph.clone())
            .with_present(mh.clone()),
        MockReconcileGate::converged(),
    );

    let s = h.uc.process_expired(ts(4000)).await.unwrap();
    assert_eq!(s.blobs_deleted, 1, "primary content (refcount 0) deleted");
    assert_eq!(s.blobs_kept, 1, "metadata blob (refcount 1) retained");
    assert_eq!(s.purged_events, 2);
    // Only the primary-content blob was deleted; metadata blob retained.
    assert_eq!(h.storage.deleted_hashes(), vec![ph.clone()]);
    let evs = purged_events(&h.store);
    assert_eq!(evs.len(), 2);
    let by_hash: std::collections::HashMap<_, _> = evs
        .iter()
        .map(|e| (e.content_hash.clone(), e.refs_remaining))
        .collect();
    assert_eq!(by_hash.get(&ph), Some(&0));
    assert_eq!(by_hash.get(&mh), Some(&1));
}

// ---------------------------------------------------------------------------
// Two-stage idempotency: transient StoragePort::delete failure does NOT
// lose the ArtifactExpired decision; sweep continues; next sweep retries.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transient_storage_delete_failure_does_not_emit_purged_and_continues() {
    let bad = Uuid::new_v4();
    let good = Uuid::new_v4();
    let bad_h = hash(HASH_PRIMARY);
    let good_h = hash(HASH_META);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![
                PendingPurge {
                    artifact_id: bad,
                    quarantine_status: QuarantineStatus::None,
                },
                PendingPurge {
                    artifact_id: good,
                    quarantine_status: QuarantineStatus::None,
                },
            ])
            .with_refs(
                bad,
                vec![PurgedRef {
                    content_hash: bad_h.clone(),
                    refs_remaining: 0,
                }],
            )
            .with_refs(
                good,
                vec![PurgedRef {
                    content_hash: good_h.clone(),
                    refs_remaining: 0,
                }],
            ),
        MockStorage::new()
            .with_present(bad_h.clone())
            .with_present(good_h.clone())
            .fail_delete_transient(bad_h.clone()),
        MockReconcileGate::converged(),
    );

    let s = h.uc.process_expired(ts(5000)).await.unwrap();

    // The bad artifact failed transiently → 1 error, NO ArtifactPurged
    // for it. The good artifact still processed (sweep continued).
    assert_eq!(s.errors, 1);
    assert_eq!(s.blobs_deleted, 1, "only the good blob deleted");
    assert_eq!(
        s.purged_events, 1,
        "only the good artifact's ArtifactPurged"
    );

    let evs = purged_events(&h.store);
    assert_eq!(evs.len(), 1);
    assert_eq!(
        evs[0].artifact_id, good,
        "the failed artifact got NO purge event"
    );

    // The ArtifactExpired decision is NOT lost: there is simply no
    // ArtifactPurged for `bad`, so a NEXT sweep would re-list it as
    // pending and retry — proven by re-running with the transient
    // fault cleared.
    let h2 = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id: bad,
                quarantine_status: QuarantineStatus::None,
            }])
            .with_refs(
                bad,
                vec![PurgedRef {
                    content_hash: bad_h.clone(),
                    refs_remaining: 0,
                }],
            ),
        MockStorage::new().with_present(bad_h.clone()),
        MockReconcileGate::converged(),
    );
    let s2 = h2.uc.process_expired(ts(6000)).await.unwrap();
    assert_eq!(s2.errors, 0);
    assert_eq!(s2.blobs_deleted, 1);
    assert_eq!(s2.purged_events, 1);
    assert_eq!(purged_events(&h2.store)[0].artifact_id, bad);
}

// ---------------------------------------------------------------------------
// Idempotent re-purge on an already-absent blob is a clean no-op
// success (delete NotFound == already gone).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn re_purge_on_already_absent_storage_is_clean_success() {
    let aid = Uuid::new_v4();
    let ph = hash(HASH_PRIMARY);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id: aid,
                quarantine_status: QuarantineStatus::None,
            }])
            .with_refs(
                aid,
                vec![PurgedRef {
                    content_hash: ph.clone(),
                    refs_remaining: 0,
                }],
            ),
        // Blob NOT present → delete returns NotFound → must be treated
        // as success-on-missing, NOT a transient error.
        MockStorage::new(),
        MockReconcileGate::converged(),
    );

    let s = h.uc.process_expired(ts(7000)).await.unwrap();
    assert_eq!(s.errors, 0, "NotFound on delete is NOT an error (inv 4)");
    assert_eq!(s.blobs_deleted, 1);
    assert_eq!(
        s.purged_events, 1,
        "ArtifactPurged still emitted (idempotent)"
    );
    let evs = purged_events(&h.store);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].refs_remaining, 0);
}

// ---------------------------------------------------------------------------
// Evidence protection — quarantined / rejected / indeterminate never purged
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invariant1_protected_artifacts_are_never_purged() {
    for status in [
        QuarantineStatus::Quarantined,
        QuarantineStatus::Rejected,
        QuarantineStatus::ScanIndeterminate,
    ] {
        let aid = Uuid::new_v4();
        let ph = hash(HASH_PRIMARY);
        let h = build(
            MockPurgeGc::new()
                .with_pending(vec![PendingPurge {
                    artifact_id: aid,
                    quarantine_status: status,
                }])
                .with_refs(
                    aid,
                    vec![PurgedRef {
                        content_hash: ph.clone(),
                        refs_remaining: 0,
                    }],
                ),
            MockStorage::new().with_present(ph.clone()),
            MockReconcileGate::converged(),
        );

        let s = h.uc.process_expired(ts(8000)).await.unwrap();
        assert_eq!(s.skipped_protected, 1, "status {status} must be skipped");
        assert_eq!(s.blobs_deleted, 0);
        assert_eq!(s.purged_events, 0);
        assert_eq!(
            h.gc.purge_call_count(),
            0,
            "must not even call purge_artifact_refs for protected {status}"
        );
        assert!(
            h.storage.deleted_hashes().is_empty(),
            "evidence blob for {status} must NEVER be deleted"
        );
        assert!(purged_events(&h.store).is_empty());
    }
}

// ---------------------------------------------------------------------------
// Error paths: list failure aborts; per-artifact tx failure continues.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_pending_failure_aborts_the_sweep() {
    let h = build(
        MockPurgeGc::new().with_list_err(),
        MockStorage::new(),
        MockReconcileGate::converged(),
    );
    let err = h.uc.process_expired(ts(9000)).await.unwrap_err();
    assert!(matches!(err, crate::error::AppError::Domain(_)));
}

#[tokio::test]
async fn purge_tx_failure_is_per_artifact_and_sweep_continues() {
    let bad = Uuid::new_v4();
    let good = Uuid::new_v4();
    let gh = hash(HASH_META);
    let h = build(
        MockPurgeGc::new()
            .with_pending(vec![
                PendingPurge {
                    artifact_id: bad,
                    quarantine_status: QuarantineStatus::None,
                },
                PendingPurge {
                    artifact_id: good,
                    quarantine_status: QuarantineStatus::None,
                },
            ])
            .with_refs(
                good,
                vec![PurgedRef {
                    content_hash: gh.clone(),
                    refs_remaining: 0,
                }],
            )
            .fail_purge_for(bad),
        MockStorage::new().with_present(gh.clone()),
        MockReconcileGate::converged(),
    );

    let s = h.uc.process_expired(ts(9100)).await.unwrap();
    assert_eq!(s.artifacts_visited, 2);
    assert_eq!(s.errors, 1, "the bad tx is one error");
    assert_eq!(s.purged_events, 1, "the good artifact still completed");
    assert_eq!(purged_events(&h.store)[0].artifact_id, good);
}

#[tokio::test]
async fn append_purged_failure_is_recorded_and_decision_retained() {
    // MockEventStore::append always Ok; to exercise the append-error
    // arm we use a publisher whose inner store fails append. Reuse a
    // tiny failing store rather than touching test_support.
    struct FailAppend;
    impl hort_domain::ports::event_store::EventStore for FailAppend {
        fn append(
            &self,
            _b: hort_domain::ports::event_store::AppendEvents,
        ) -> BoxFuture<'_, DomainResult<hort_domain::ports::event_store::AppendResult>> {
            Box::pin(async { Err(DomainError::Invariant("append boom".into())) })
        }
        fn read_stream(
            &self,
            _s: &hort_domain::events::StreamId,
            _f: hort_domain::ports::event_store::ReadFrom,
            _m: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::events::PersistedEvent>>> {
            Box::pin(async { Ok(vec![]) })
        }
        fn read_category(
            &self,
            _c: hort_domain::events::StreamCategory,
            _f: hort_domain::ports::event_store::SubscribeFrom,
            _m: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::events::PersistedEvent>>> {
            Box::pin(async { Ok(vec![]) })
        }
        fn delete_stream(
            &self,
            _s: hort_domain::events::StreamId,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn archive_stream(
            &self,
            _s: hort_domain::events::StreamId,
            _t: &str,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let aid = Uuid::new_v4();
    let ph = hash(HASH_PRIMARY);
    let gc = Arc::new(
        MockPurgeGc::new()
            .with_pending(vec![PendingPurge {
                artifact_id: aid,
                quarantine_status: QuarantineStatus::None,
            }])
            .with_refs(
                aid,
                vec![PurgedRef {
                    content_hash: ph.clone(),
                    refs_remaining: 0,
                }],
            ),
    );
    let storage = Arc::new(MockStorage::new().with_present(ph.clone()));
    let publisher = wrap_for_test(Arc::new(FailAppend));
    let uc = PurgeUseCase::new(
        gc.clone(),
        storage.clone(),
        publisher,
        MockReconcileGate::converged(),
    );

    let s = uc.process_expired(ts(9200)).await.unwrap();
    // Storage delete happened (idempotent); append failed → error
    // recorded, no purged_events, sweep returns Ok.
    assert_eq!(s.blobs_deleted, 1);
    assert_eq!(s.purged_events, 0);
    assert_eq!(s.errors, 1);
}

// ---------------------------------------------------------------------------
// Metric: hort_retention_purged_total fires with the documented labels.
// ---------------------------------------------------------------------------

mod metrics_emission_tests {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use std::collections::HashMap;

    type SnapEntry = (
        metrics_util::CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn capture<F>(f: F) -> Vec<SnapEntry>
    where
        F: FnOnce() -> futures::future::BoxFuture<'static, ()> + Send + 'static,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(f());
        });
        snapshotter.snapshot().into_vec()
    }

    fn counter(snap: &[SnapEntry], name: &str, result: &str) -> Option<u64> {
        for (key, _, _, value) in snap {
            if key.key().name() != name {
                continue;
            }
            let labels: HashMap<&str, &str> =
                key.key().labels().map(|l| (l.key(), l.value())).collect();
            if labels.get("result") != Some(&result) {
                continue;
            }
            if let DebugValue::Counter(v) = value {
                return Some(*v);
            }
        }
        None
    }

    #[test]
    fn purged_total_fires_success_blob_kept_and_storage_error() {
        let snap = capture(|| {
            Box::pin(async {
                let success_id = Uuid::new_v4();
                let kept_id = Uuid::new_v4();
                let err_id = Uuid::new_v4();
                let sh = hash(HASH_PRIMARY);
                let kh = hash(HASH_META);
                // a third valid distinct hash for the storage-error case
                let eh = hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

                let h = build(
                    MockPurgeGc::new()
                        .with_pending(vec![
                            PendingPurge {
                                artifact_id: success_id,
                                quarantine_status: QuarantineStatus::None,
                            },
                            PendingPurge {
                                artifact_id: kept_id,
                                quarantine_status: QuarantineStatus::None,
                            },
                            PendingPurge {
                                artifact_id: err_id,
                                quarantine_status: QuarantineStatus::None,
                            },
                        ])
                        .with_refs(
                            success_id,
                            vec![PurgedRef {
                                content_hash: sh.clone(),
                                refs_remaining: 0,
                            }],
                        )
                        .with_refs(
                            kept_id,
                            vec![PurgedRef {
                                content_hash: kh.clone(),
                                refs_remaining: 2,
                            }],
                        )
                        .with_refs(
                            err_id,
                            vec![PurgedRef {
                                content_hash: eh.clone(),
                                refs_remaining: 0,
                            }],
                        ),
                    MockStorage::new()
                        .with_present(sh.clone())
                        .with_present(kh.clone())
                        .with_present(eh.clone())
                        .fail_delete_transient(eh.clone()),
                    MockReconcileGate::converged(),
                );
                let _ = h.uc.process_expired(ts(1)).await.unwrap();
            })
        });

        assert_eq!(
            counter(&snap, "hort_retention_purged_total", "success"),
            Some(1)
        );
        assert_eq!(
            counter(&snap, "hort_retention_purged_total", "blob_kept"),
            Some(1)
        );
        assert_eq!(
            counter(&snap, "hort_retention_purged_total", "storage_error"),
            Some(1)
        );
    }
}
