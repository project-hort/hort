//! `EventStoreRetentionUseCase::archive_terminal_streams`
//! unit tests.
//!
//! `hort-app` is the 100%-coverage tier (mock every port). Every branch
//! is pinned here:
//! - empty candidate set → no-op.
//! - TerminalGated terminal + floor-elapsed + `Delete` → `delete_stream`,
//!   `deleted` tallied.
//! - TerminalGated terminal + elapsed + `Archive` → `archive_stream`
//!   with the exact `format!("{prefix}/{stream_id}")` target.
//! - non-terminal tail → `skipped_non_terminal` + warn.
//! - floor not elapsed → `skipped_floor_not_elapsed`.
//! - floor boundary: exactly-at (sealed) vs one-second-short (skipped),
//!   pinned `now`.
//! - seal chokepoint failure → `errors`, sweep continues (second
//!   candidate still processed) — the fail-safe path.
//! - meta-stream candidate → `skipped_meta_stream` + no chokepoint.
//! - idempotent re-run: empty `read_stream` → `skipped_already_sealed`.
//! - AgeGated category (no terminal): sealed on age alone (elapsed),
//!   skipped (not elapsed) — and NO `read_stream` is performed.
//! - unregistered category → `skipped_unregistered_category`.
//! - mixed batch full-tally.
//! - `list_terminal_candidates` port error → `Err` (whole sweep
//!   aborts, vs per-stream errors which continue).
//! - a `DebuggingRecorder` assertion that
//!   `hort_event_store_streams_archived_total{result=…}` fires with the
//!   documented `{archived, deleted, skipped}` label values.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{
    Actor, ApiActor, ArtifactIngested, ArtifactPurged, AuthenticationAttempted, DomainEvent,
    IngestSource, PersistedEvent, StreamCategory, StreamId,
};
use hort_domain::ports::event_store::{
    AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
};
use hort_domain::ports::terminal_stream_reader::{TerminalStreamCandidate, TerminalStreamReader};
use hort_domain::ports::BoxFuture;
use hort_domain::types::ContentHash;

use crate::event_store_publisher::wrap_for_test;
use crate::use_cases::eventstore_retention_use_case::{
    CategoryRetentionRule, EventStoreRetentionUseCase, SealMode, StreamRetentionModeRef,
};

const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).unwrap()
}

fn artifact_stream(id: Uuid) -> String {
    StreamId::artifact(id).to_string()
}

fn auth_stream(date: chrono::NaiveDate) -> String {
    StreamId::auth_attempts(date).to_string()
}

/// A 36mo-ish floor in seconds-comparable units. Tests pin `now` and
/// `first_event_at` against this so the C-1 comparison is exact.
fn floor_secs(secs: i64) -> Duration {
    Duration::seconds(secs)
}

fn purged_persisted(artifact_id: Uuid, position: u64) -> PersistedEvent {
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: StreamId::artifact(artifact_id),
        stream_position: position,
        global_position: position + 1,
        event: DomainEvent::ArtifactPurged(ArtifactPurged {
            artifact_id,
            content_hash: HASH_A.parse::<ContentHash>().unwrap(),
            refs_remaining: 0,
            purged_at: ts(10),
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: Actor::Api(ApiActor {
            user_id: Uuid::new_v4(),
        }),
        event_version: 1,
        stored_at: ts(10),
    }
}

fn ingested_persisted(artifact_id: Uuid, position: u64) -> PersistedEvent {
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: StreamId::artifact(artifact_id),
        stream_position: position,
        global_position: position + 1,
        event: DomainEvent::ArtifactIngested(ArtifactIngested {
            artifact_id,
            repository_id: Uuid::new_v4(),
            name: "pkg".into(),
            version: Some("1.0.0".into()),
            sha256: HASH_A.parse::<ContentHash>().unwrap(),
            size_bytes: 1,
            source: IngestSource::Direct,
            metadata: serde_json::Value::Null,
            metadata_blob: None,
            upstream_published_at: None,
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: Actor::Api(ApiActor {
            user_id: Uuid::new_v4(),
        }),
        event_version: 1,
        stored_at: ts(10),
    }
}

fn auth_persisted(stream_id: StreamId, position: u64) -> PersistedEvent {
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id,
        stream_position: position,
        global_position: position + 1,
        event: DomainEvent::AuthenticationAttempted(AuthenticationAttempted {
            client_ip: "127.0.0.1".parse().unwrap(),
            result: "local_invalid_credentials".into(),
            external_id_if_decoded: None,
            at: ts(10),
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: hort_domain::events::system_actor(),
        event_version: 1,
        stored_at: ts(10),
    }
}

// ---------------------------------------------------------------------------
// MockTerminalStreamReader
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockReader {
    candidates: Mutex<Vec<TerminalStreamCandidate>>,
    list_err: AtomicBool,
    list_calls: AtomicUsize,
}

impl MockReader {
    fn new() -> Self {
        Self::default()
    }
    fn with(self, c: Vec<TerminalStreamCandidate>) -> Self {
        *self.candidates.lock().unwrap() = c;
        self
    }
    fn with_list_err(self) -> Self {
        self.list_err.store(true, Ordering::SeqCst);
        self
    }
}

impl TerminalStreamReader for MockReader {
    fn list_terminal_candidates(
        &self,
    ) -> BoxFuture<'_, DomainResult<Vec<TerminalStreamCandidate>>> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        let err = self.list_err.load(Ordering::SeqCst);
        let c = self.candidates.lock().unwrap().clone();
        Box::pin(async move {
            if err {
                Err(DomainError::Invariant("candidate list failed".into()))
            } else {
                Ok(c)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// MockEventStore — dedicated (the shared test_support::MockEventStore's
// delete_stream/archive_stream are silent no-ops with no recording and
// no failure injection; these tests need to assert which chokepoint fired
// with which target AND inject a chokepoint failure for the fail-safe path).
// Self-contained so test_support stays untouched.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockEventStore {
    /// stream_id string → seeded events for `read_stream`.
    streams: Mutex<std::collections::HashMap<String, Vec<PersistedEvent>>>,
    /// stream_id strings whose `read_stream` returns an error.
    read_err_for: Mutex<Vec<String>>,
    deleted: Mutex<Vec<String>>,
    archived: Mutex<Vec<(String, String)>>,
    /// stream_id strings whose chokepoint call returns an error.
    seal_err_for: Mutex<Vec<String>>,
}

impl MockEventStore {
    fn new() -> Self {
        Self::default()
    }
    fn seed_stream(self, stream_id: &str, events: Vec<PersistedEvent>) -> Self {
        self.streams
            .lock()
            .unwrap()
            .insert(stream_id.to_owned(), events);
        self
    }
    fn fail_read_for(self, stream_id: &str) -> Self {
        self.read_err_for.lock().unwrap().push(stream_id.to_owned());
        self
    }
    fn fail_seal_for(self, stream_id: &str) -> Self {
        self.seal_err_for.lock().unwrap().push(stream_id.to_owned());
        self
    }
    fn deleted_streams(&self) -> Vec<String> {
        self.deleted.lock().unwrap().clone()
    }
    fn archived_streams(&self) -> Vec<(String, String)> {
        self.archived.lock().unwrap().clone()
    }
}

impl EventStore for MockEventStore {
    fn append(&self, _b: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
        // The retention use case never appends directly (the adapter
        // handles the StreamSealed append internally); a call here is a bug.
        Box::pin(async { unreachable!("retention use case must not append directly") })
    }
    fn read_stream(
        &self,
        stream_id: &StreamId,
        _from: ReadFrom,
        _max: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
        let key = stream_id.to_string();
        let err = self.read_err_for.lock().unwrap().contains(&key);
        let events = self
            .streams
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .unwrap_or_default();
        Box::pin(async move {
            if err {
                Err(DomainError::Invariant(format!("read_stream boom: {key}")))
            } else {
                Ok(events)
            }
        })
    }
    fn read_category(
        &self,
        _c: StreamCategory,
        _f: SubscribeFrom,
        _m: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
        Box::pin(async { Ok(vec![]) })
    }
    fn delete_stream(&self, stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>> {
        let key = stream_id.to_string();
        let fail = self.seal_err_for.lock().unwrap().contains(&key);
        self.deleted.lock().unwrap().push(key.clone());
        Box::pin(async move {
            if fail {
                Err(DomainError::Invariant(format!(
                    "delete_stream chokepoint blocked (hort_retention_role \
                     not yet wired): {key}"
                )))
            } else {
                Ok(())
            }
        })
    }
    fn archive_stream(&self, stream_id: StreamId, target: &str) -> BoxFuture<'_, DomainResult<()>> {
        let key = stream_id.to_string();
        let fail = self.seal_err_for.lock().unwrap().contains(&key);
        self.archived
            .lock()
            .unwrap()
            .push((key.clone(), target.to_owned()));
        Box::pin(async move {
            if fail {
                Err(DomainError::Invariant(format!(
                    "archive_stream chokepoint blocked: {key}"
                )))
            } else {
                Ok(())
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    uc: EventStoreRetentionUseCase,
    store: Arc<MockEventStore>,
}

fn artifact_rule(floor: Duration) -> CategoryRetentionRule {
    CategoryRetentionRule {
        category: StreamCategory::Artifact,
        floor,
        mode: SealMode::TerminalGated {
            terminal_event_type: "ArtifactPurged",
        },
    }
}

fn auth_rule(floor: Duration) -> CategoryRetentionRule {
    CategoryRetentionRule {
        category: StreamCategory::AuthAttempts,
        floor,
        mode: SealMode::AgeGated,
    }
}

fn build(
    reader: MockReader,
    store: MockEventStore,
    rules: Vec<CategoryRetentionRule>,
    mode: StreamRetentionModeRef,
) -> Harness {
    let store = Arc::new(store);
    let publisher = wrap_for_test(store.clone());
    let uc = EventStoreRetentionUseCase::new(Arc::new(reader), publisher, rules, mode);
    Harness { uc, store }
}

fn candidate(
    stream_id: String,
    category: StreamCategory,
    first_event_at: DateTime<Utc>,
    last_event_type: &str,
) -> TerminalStreamCandidate {
    TerminalStreamCandidate {
        stream_id,
        category,
        first_event_at,
        last_event_at: first_event_at,
        last_event_type: last_event_type.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Empty / list error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_candidate_set_is_noop() {
    let h = build(
        MockReader::new(),
        MockEventStore::new(),
        vec![artifact_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s, Default::default());
    assert!(h.store.deleted_streams().is_empty());
    assert!(h.store.archived_streams().is_empty());
}

#[tokio::test]
async fn list_candidates_error_aborts_whole_sweep() {
    let h = build(
        MockReader::new().with_list_err(),
        MockEventStore::new(),
        vec![artifact_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    let err = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap_err();
    assert!(matches!(err, crate::error::AppError::Domain(_)));
    assert!(h.store.deleted_streams().is_empty());
}

// ---------------------------------------------------------------------------
// TerminalGated: terminal + floor-elapsed + Delete → delete_stream
// ---------------------------------------------------------------------------

#[tokio::test]
async fn terminal_elapsed_delete_seals_via_delete_stream() {
    let aid = Uuid::new_v4();
    let sid = artifact_stream(aid);
    let h = build(
        MockReader::new().with(vec![candidate(
            sid.clone(),
            StreamCategory::Artifact,
            ts(1_000),
            "ArtifactPurged",
        )]),
        MockEventStore::new().seed_stream(&sid, vec![purged_persisted(aid, 5)]),
        vec![artifact_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    // now - first_event_at = 9000 >= floor 100 → seal.
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s.candidates_visited, 1);
    assert_eq!(s.deleted, 1);
    assert_eq!(s.archived, 0);
    assert_eq!(s.errors, 0);
    assert_eq!(h.store.deleted_streams(), vec![sid]);
    assert!(h.store.archived_streams().is_empty());
}

// ---------------------------------------------------------------------------
// TerminalGated: terminal + elapsed + Archive → archive_stream + target
// ---------------------------------------------------------------------------

#[tokio::test]
async fn terminal_elapsed_archive_seals_with_exact_target_string() {
    let aid = Uuid::new_v4();
    let sid = artifact_stream(aid);
    let h = build(
        MockReader::new().with(vec![candidate(
            sid.clone(),
            StreamCategory::Artifact,
            ts(1_000),
            "ArtifactPurged",
        )]),
        MockEventStore::new().seed_stream(&sid, vec![purged_persisted(aid, 0)]),
        vec![artifact_rule(floor_secs(100))],
        StreamRetentionModeRef::Archive {
            target_prefix: "s3://cold/hort".to_owned(),
        },
    );
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s.archived, 1);
    assert_eq!(s.deleted, 0);
    assert!(h.store.deleted_streams().is_empty());
    assert_eq!(
        h.store.archived_streams(),
        vec![(sid.clone(), format!("s3://cold/hort/{sid}"))]
    );
}

// ---------------------------------------------------------------------------
// Non-terminal tail → skipped_non_terminal, no chokepoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_terminal_tail_is_skipped_not_sealed() {
    let aid = Uuid::new_v4();
    let sid = artifact_stream(aid);
    let h = build(
        MockReader::new().with(vec![candidate(
            sid.clone(),
            StreamCategory::Artifact,
            ts(1_000),
            "ArtifactIngested",
        )]),
        // Tail is ArtifactIngested, NOT the ArtifactPurged terminal.
        MockEventStore::new().seed_stream(&sid, vec![ingested_persisted(aid, 0)]),
        vec![artifact_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s.skipped_non_terminal, 1);
    assert_eq!(s.deleted, 0);
    assert_eq!(s.errors, 0);
    assert!(h.store.deleted_streams().is_empty());
}

// ---------------------------------------------------------------------------
// Floor not elapsed → skipped_floor_not_elapsed, no chokepoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn floor_not_elapsed_is_skipped() {
    let aid = Uuid::new_v4();
    let sid = artifact_stream(aid);
    let h = build(
        MockReader::new().with(vec![candidate(
            sid.clone(),
            StreamCategory::Artifact,
            ts(9_950),
            "ArtifactPurged",
        )]),
        MockEventStore::new().seed_stream(&sid, vec![purged_persisted(aid, 0)]),
        vec![artifact_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    // now - first = 10_000 - 9_950 = 50 < floor 100 → NOT sealed.
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s.skipped_floor_not_elapsed, 1);
    assert_eq!(s.deleted, 0);
    assert!(h.store.deleted_streams().is_empty());
}

// ---------------------------------------------------------------------------
// Floor boundary: exactly-at seals; one-second-short skips. Pinned now.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn floor_boundary_exactly_at_seals_one_second_short_skips() {
    // exactly-at: now - first == floor → elapsed >= floor → seal.
    {
        let aid = Uuid::new_v4();
        let sid = artifact_stream(aid);
        let h = build(
            MockReader::new().with(vec![candidate(
                sid.clone(),
                StreamCategory::Artifact,
                ts(9_900),
                "ArtifactPurged",
            )]),
            MockEventStore::new().seed_stream(&sid, vec![purged_persisted(aid, 0)]),
            vec![artifact_rule(floor_secs(100))],
            StreamRetentionModeRef::Delete,
        );
        // 10_000 - 9_900 = 100 == floor → sealed.
        let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
        assert_eq!(s.deleted, 1, "exactly-at-floor must seal");
        assert_eq!(s.skipped_floor_not_elapsed, 0);
    }
    // one-second-short: elapsed = floor - 1 → skip.
    {
        let aid = Uuid::new_v4();
        let sid = artifact_stream(aid);
        let h = build(
            MockReader::new().with(vec![candidate(
                sid.clone(),
                StreamCategory::Artifact,
                ts(9_901),
                "ArtifactPurged",
            )]),
            MockEventStore::new().seed_stream(&sid, vec![purged_persisted(aid, 0)]),
            vec![artifact_rule(floor_secs(100))],
            StreamRetentionModeRef::Delete,
        );
        // 10_000 - 9_901 = 99 < 100 → NOT sealed.
        let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
        assert_eq!(s.deleted, 0, "one-second-short must NOT seal");
        assert_eq!(s.skipped_floor_not_elapsed, 1);
    }
}

// ---------------------------------------------------------------------------
// Seal chokepoint failure → errors, sweep continues (fail-safe path)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn chokepoint_failure_records_error_and_sweep_continues() {
    let bad = Uuid::new_v4();
    let good = Uuid::new_v4();
    let bad_sid = artifact_stream(bad);
    let good_sid = artifact_stream(good);
    let h = build(
        MockReader::new().with(vec![
            candidate(
                bad_sid.clone(),
                StreamCategory::Artifact,
                ts(1_000),
                "ArtifactPurged",
            ),
            candidate(
                good_sid.clone(),
                StreamCategory::Artifact,
                ts(1_000),
                "ArtifactPurged",
            ),
        ]),
        MockEventStore::new()
            .seed_stream(&bad_sid, vec![purged_persisted(bad, 0)])
            .seed_stream(&good_sid, vec![purged_persisted(good, 0)])
            // The unprivileged-role DELETE block when hort_retention_role
            // is not wired manifests exactly as this per-stream
            // chokepoint Err.
            .fail_seal_for(&bad_sid),
        vec![artifact_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s.candidates_visited, 2);
    assert_eq!(s.errors, 1, "the blocked stream is one error");
    assert_eq!(s.deleted, 1, "the second stream still sealed");
    // Both delete_stream calls were attempted (the bad one errored).
    let deleted = h.store.deleted_streams();
    assert!(deleted.contains(&bad_sid));
    assert!(deleted.contains(&good_sid));
}

// ---------------------------------------------------------------------------
// Meta-stream candidate → skipped_meta_stream, no chokepoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn meta_stream_candidate_is_skipped_never_sealed() {
    let meta = StreamId::eventstore_retention().to_string();
    let h = build(
        MockReader::new().with(vec![candidate(
            meta.clone(),
            StreamCategory::Admin,
            ts(1),
            "StreamSealed",
        )]),
        MockEventStore::new(),
        // Even with an Admin rule registered, the meta-stream guard
        // fires FIRST (defence-in-depth, before rule lookup).
        vec![CategoryRetentionRule {
            category: StreamCategory::Admin,
            floor: floor_secs(0),
            mode: SealMode::AgeGated,
        }],
        StreamRetentionModeRef::Delete,
    );
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s.skipped_meta_stream, 1);
    assert_eq!(s.deleted, 0);
    assert!(
        h.store.deleted_streams().is_empty(),
        "the never-deleted audit-meta stream must NEVER be sealed"
    );
}

// ---------------------------------------------------------------------------
// Idempotent re-run: empty read_stream → skipped_already_sealed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_read_stream_is_already_sealed_idempotent() {
    let aid = Uuid::new_v4();
    let sid = artifact_stream(aid);
    let h = build(
        MockReader::new().with(vec![candidate(
            sid.clone(),
            StreamCategory::Artifact,
            ts(1_000),
            "ArtifactPurged",
        )]),
        // No seed → read_stream returns empty → already sealed.
        MockEventStore::new(),
        vec![artifact_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s.skipped_already_sealed, 1);
    assert_eq!(s.deleted, 0);
    assert!(h.store.deleted_streams().is_empty());
}

// ---------------------------------------------------------------------------
// Terminal-proof read failure → errors, no seal (fail-safe)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn terminal_proof_read_failure_records_error_and_does_not_seal() {
    let aid = Uuid::new_v4();
    let sid = artifact_stream(aid);
    let h = build(
        MockReader::new().with(vec![candidate(
            sid.clone(),
            StreamCategory::Artifact,
            ts(1_000),
            "ArtifactPurged",
        )]),
        MockEventStore::new()
            .seed_stream(&sid, vec![purged_persisted(aid, 0)])
            .fail_read_for(&sid),
        vec![artifact_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s.errors, 1);
    assert_eq!(s.deleted, 0);
    assert!(h.store.deleted_streams().is_empty());
}

// ---------------------------------------------------------------------------
// AgeGated (no terminal): sealed on age alone; NO read_stream performed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn age_gated_seals_on_age_alone_without_reading_the_stream() {
    let date = chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let sid = auth_stream(date);
    // Deliberately fail read_stream for this stream: an AgeGated
    // category MUST NOT read it (no terminal proof). If the use case
    // wrongly read it, this would surface as an error and 0 deleted.
    let h = build(
        MockReader::new().with(vec![candidate(
            sid.clone(),
            StreamCategory::AuthAttempts,
            ts(1_000),
            // last_event_type is irrelevant for AgeGated.
            "AuthenticationAttempted",
        )]),
        MockEventStore::new()
            .seed_stream(&sid, vec![auth_persisted(sid.parse().unwrap(), 0)])
            .fail_read_for(&sid),
        vec![auth_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(
        s.deleted, 1,
        "AgeGated must seal on age alone without reading the stream"
    );
    assert_eq!(
        s.errors, 0,
        "no read_stream means the seeded read-fail never fires"
    );
    assert_eq!(h.store.deleted_streams(), vec![sid]);
}

#[tokio::test]
async fn age_gated_not_elapsed_is_skipped() {
    let date = chrono::NaiveDate::from_ymd_opt(2026, 2, 2).unwrap();
    let sid = auth_stream(date);
    let h = build(
        MockReader::new().with(vec![candidate(
            sid.clone(),
            StreamCategory::AuthAttempts,
            ts(9_950),
            "AuthenticationAttempted",
        )]),
        MockEventStore::new(),
        vec![auth_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    // 10_000 - 9_950 = 50 < 100 → NOT sealed.
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s.skipped_floor_not_elapsed, 1);
    assert_eq!(s.deleted, 0);
}

// ---------------------------------------------------------------------------
// Unregistered category → skipped_unregistered_category
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unregistered_category_is_skipped() {
    let sid = StreamId::policy(Uuid::new_v4()).to_string();
    let h = build(
        MockReader::new().with(vec![candidate(
            sid.clone(),
            StreamCategory::Policy,
            ts(1),
            "PolicyArchived",
        )]),
        MockEventStore::new(),
        // Only Artifact registered; Policy has no rule.
        vec![artifact_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s.skipped_unregistered_category, 1);
    assert_eq!(s.deleted, 0);
    assert!(h.store.deleted_streams().is_empty());
}

// ---------------------------------------------------------------------------
// Mixed batch — full tally across every outcome bucket
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mixed_batch_tallies_every_outcome() {
    let seal_id = Uuid::new_v4();
    let non_term_id = Uuid::new_v4();
    let floor_id = Uuid::new_v4();
    let sealed_already_id = Uuid::new_v4();
    let blocked_id = Uuid::new_v4();
    let date = chrono::NaiveDate::from_ymd_opt(2026, 3, 3).unwrap();

    let seal_sid = artifact_stream(seal_id);
    let non_term_sid = artifact_stream(non_term_id);
    let floor_sid = artifact_stream(floor_id);
    let already_sid = artifact_stream(sealed_already_id);
    let blocked_sid = artifact_stream(blocked_id);
    let age_sid = auth_stream(date);
    let meta = StreamId::eventstore_retention().to_string();
    let unreg_sid = StreamId::policy(Uuid::new_v4()).to_string();

    let h = build(
        MockReader::new().with(vec![
            candidate(
                seal_sid.clone(),
                StreamCategory::Artifact,
                ts(1_000),
                "ArtifactPurged",
            ),
            candidate(
                non_term_sid.clone(),
                StreamCategory::Artifact,
                ts(1_000),
                "x",
            ),
            candidate(
                floor_sid.clone(),
                StreamCategory::Artifact,
                ts(9_999),
                "ArtifactPurged",
            ),
            candidate(
                already_sid.clone(),
                StreamCategory::Artifact,
                ts(1_000),
                "ArtifactPurged",
            ),
            candidate(
                blocked_sid.clone(),
                StreamCategory::Artifact,
                ts(1_000),
                "ArtifactPurged",
            ),
            candidate(
                age_sid.clone(),
                StreamCategory::AuthAttempts,
                ts(1_000),
                "AuthenticationAttempted",
            ),
            candidate(meta.clone(), StreamCategory::Admin, ts(1), "StreamSealed"),
            candidate(
                unreg_sid.clone(),
                StreamCategory::Policy,
                ts(1),
                "PolicyArchived",
            ),
        ]),
        MockEventStore::new()
            .seed_stream(&seal_sid, vec![purged_persisted(seal_id, 0)])
            .seed_stream(&non_term_sid, vec![ingested_persisted(non_term_id, 0)])
            .seed_stream(&floor_sid, vec![purged_persisted(floor_id, 0)])
            // already_sid: no seed → empty read → already sealed.
            .seed_stream(&blocked_sid, vec![purged_persisted(blocked_id, 0)])
            .seed_stream(&age_sid, vec![auth_persisted(age_sid.parse().unwrap(), 0)])
            .fail_seal_for(&blocked_sid),
        vec![artifact_rule(floor_secs(100)), auth_rule(floor_secs(100))],
        StreamRetentionModeRef::Delete,
    );
    let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
    assert_eq!(s.candidates_visited, 8);
    assert_eq!(s.deleted, 2, "seal_sid + age_sid");
    assert_eq!(s.skipped_non_terminal, 1);
    assert_eq!(s.skipped_floor_not_elapsed, 1);
    assert_eq!(s.skipped_already_sealed, 1);
    assert_eq!(s.skipped_meta_stream, 1);
    assert_eq!(s.skipped_unregistered_category, 1);
    assert_eq!(s.errors, 1, "blocked_sid chokepoint Err");
    assert!(!h.store.deleted_streams().contains(&meta));
}

// ---------------------------------------------------------------------------
// Metric: hort_event_store_streams_archived_total fires with documented
// {archived, deleted, skipped} label values.
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
    fn streams_archived_fires_archived_deleted_and_skipped() {
        let snap = capture(|| {
            Box::pin(async {
                let del_id = Uuid::new_v4();
                let arch_id = Uuid::new_v4();
                let skip_id = Uuid::new_v4();
                let del_sid = artifact_stream(del_id);
                let arch_sid = artifact_stream(arch_id);
                let skip_sid = artifact_stream(skip_id);

                // One Delete-mode sweep producing a `deleted` + a
                // `skipped` (non-terminal).
                let h = build(
                    MockReader::new().with(vec![
                        candidate(
                            del_sid.clone(),
                            StreamCategory::Artifact,
                            ts(1_000),
                            "ArtifactPurged",
                        ),
                        candidate(
                            skip_sid.clone(),
                            StreamCategory::Artifact,
                            ts(1_000),
                            "ArtifactIngested",
                        ),
                    ]),
                    MockEventStore::new()
                        .seed_stream(&del_sid, vec![purged_persisted(del_id, 0)])
                        .seed_stream(&skip_sid, vec![ingested_persisted(skip_id, 0)]),
                    vec![artifact_rule(floor_secs(100))],
                    StreamRetentionModeRef::Delete,
                );
                let _ = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();

                // A second Archive-mode sweep producing `archived`.
                let h2 = build(
                    MockReader::new().with(vec![candidate(
                        arch_sid.clone(),
                        StreamCategory::Artifact,
                        ts(1_000),
                        "ArtifactPurged",
                    )]),
                    MockEventStore::new()
                        .seed_stream(&arch_sid, vec![purged_persisted(arch_id, 0)]),
                    vec![artifact_rule(floor_secs(100))],
                    StreamRetentionModeRef::Archive {
                        target_prefix: "s3://cold".to_owned(),
                    },
                );
                let _ = h2.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
            })
        });

        assert_eq!(
            counter(&snap, "hort_event_store_streams_archived_total", "deleted"),
            Some(1)
        );
        assert_eq!(
            counter(&snap, "hort_event_store_streams_archived_total", "skipped"),
            Some(1)
        );
        assert_eq!(
            counter(&snap, "hort_event_store_streams_archived_total", "archived"),
            Some(1)
        );
    }
}

// ---------------------------------------------------------------------------
// canonical_retention_rules builder
//
// The pure `hort-app` builder takes the resolved C-1 floor `Duration`s as
// explicit params (NOT the `hort-server` `AuditRetentionFloors` struct —
// `hort-app` must not depend on `hort-server`) and returns the canonical
// `Vec<CategoryRetentionRule>`: `AuthAttempts` (AgeGated, ≥6mo
// Authentication floor) and the artifact-lifecycle terminal-gated rule
// (`ArtifactPurged`), plus the DownloadAudit and TokenUse categories.
// ---------------------------------------------------------------------------

mod canonical_rules_tests {
    use super::*;
    use crate::use_cases::eventstore_retention_use_case::canonical_retention_rules;

    /// The ≥6mo Authentication audit-retention floor, as the composition
    /// root will pass it (`AuditRetentionFloors::MIN_AUTHENTICATION_DAYS`
    /// = 180d). These tests only assert the builder threads whatever
    /// floor it is given to the `AuthAttempts` rule; they do not
    /// redefine the value.
    fn auth_floor() -> Duration {
        Duration::days(180)
    }

    /// The artifact-lifecycle floor (default
    /// 36mo = 1080d). Distinct from `auth_floor()` so the per-rule
    /// threading is unambiguous.
    fn lifecycle_floor() -> Duration {
        Duration::days(1080)
    }

    /// The ≥90d `artifact_downloaded` audit-retention floor, as the
    /// composition root passes it
    /// (`AuditRetentionFloors::MIN_ARTIFACT_DOWNLOADED_DAYS` = 90d).
    /// Distinct from `auth_floor()` / `lifecycle_floor()` so the
    /// per-rule threading is unambiguous.
    fn download_audit_floor() -> Duration {
        Duration::days(90)
    }

    /// The ≥36mo `api_token_used` credential-audit floor,
    /// as the composition root passes it
    /// (`AuditRetentionFloors::MIN_API_TOKEN_USED_DAYS` = 1080d). Note
    /// this equals `lifecycle_floor()` numerically; the threading test
    /// (`builder_threads_distinct_floors_independently`) uses
    /// deliberately-distinct values so a cross-wire is still caught.
    /// (B13 registration.)
    fn api_token_used_floor() -> Duration {
        Duration::days(1080)
    }

    #[test]
    fn contains_auth_attempts_age_gated_rule_with_supplied_floor() {
        let rules = canonical_retention_rules(
            auth_floor(),
            lifecycle_floor(),
            download_audit_floor(),
            api_token_used_floor(),
        );
        let auth = rules
            .iter()
            .find(|r| r.category == StreamCategory::AuthAttempts)
            .expect("canonical set must register an AuthAttempts rule (B14)");
        assert_eq!(
            auth.mode,
            SealMode::AgeGated,
            "auth-{{date}} streams have no terminal — AgeGated"
        );
        assert_eq!(
            auth.floor,
            auth_floor(),
            "the ≥6mo Authentication floor must be threaded verbatim"
        );
    }

    #[test]
    fn contains_artifact_lifecycle_terminal_gated_rule_with_supplied_floor() {
        let rules = canonical_retention_rules(
            auth_floor(),
            lifecycle_floor(),
            download_audit_floor(),
            api_token_used_floor(),
        );
        let artifact = rules
            .iter()
            .find(|r| r.category == StreamCategory::Artifact)
            .expect("canonical set must register the artifact-lifecycle rule");
        assert_eq!(
            artifact.mode,
            SealMode::TerminalGated {
                terminal_event_type: "ArtifactPurged",
            },
            "artifact-lifecycle streams seal only on the ArtifactPurged terminal"
        );
        assert_eq!(
            artifact.floor,
            lifecycle_floor(),
            "the artifact_lifecycle floor must be threaded verbatim"
        );
    }

    #[test]
    fn builder_is_seeded_with_the_b5_categories_plus_b12_download_audit_and_b13_token_use() {
        // B14 seeded AuthAttempts + artifact-lifecycle. B12 appended
        // the DownloadAudit registration. B13 (this PR) appends the
        // TokenUse registration.
        let rules = canonical_retention_rules(
            auth_floor(),
            lifecycle_floor(),
            download_audit_floor(),
            api_token_used_floor(),
        );
        assert_eq!(
            rules.len(),
            4,
            "B14 seeds AuthAttempts + artifact-lifecycle; B12 appends \
             DownloadAudit; B13 appends TokenUse"
        );
        let categories: Vec<StreamCategory> = rules.iter().map(|r| r.category).collect();
        assert!(categories.contains(&StreamCategory::AuthAttempts));
        assert!(categories.contains(&StreamCategory::Artifact));
        assert!(categories.contains(&StreamCategory::DownloadAudit));
        // B13's per-use TokenUse registration is now present.
        assert!(categories.contains(&StreamCategory::TokenUse));
        // `User` is NEVER a canonical_retention_rules entry — it is
        // only a `floor_for` mapping for the user CRUD lifecycle
        // stream (issuance/revocation); the per-use stream is its own
        // `TokenUse` category.
        assert!(!categories.contains(&StreamCategory::User));
    }

    /// The DownloadAudit rule is AgeGated (rotated audit stream,
    /// no terminal event — same shape as the AuthAttempts rule) and
    /// carries the supplied download-audit floor verbatim.
    #[test]
    fn contains_download_audit_age_gated_rule_with_supplied_floor() {
        let rules = canonical_retention_rules(
            auth_floor(),
            lifecycle_floor(),
            download_audit_floor(),
            api_token_used_floor(),
        );
        let dl = rules
            .iter()
            .find(|r| r.category == StreamCategory::DownloadAudit)
            .expect("canonical set must register a DownloadAudit rule (B12)");
        assert_eq!(
            dl.mode,
            SealMode::AgeGated,
            "download-audit streams have no terminal — AgeGated"
        );
        assert_eq!(
            dl.floor,
            download_audit_floor(),
            "the ≥90d artifact_downloaded floor must be threaded verbatim"
        );
    }

    /// Boundary: the registered DownloadAudit floor is at-or-above
    /// the ≥90d download-audit minimum. Pinning this surfaces a policy
    /// change at review time (the same discipline as the auth ≥6mo
    /// boundary tests below).
    #[test]
    fn download_audit_floor_is_at_or_above_the_90d_minimum() {
        let rules = canonical_retention_rules(
            auth_floor(),
            lifecycle_floor(),
            Duration::days(90),
            api_token_used_floor(),
        );
        let dl = rules
            .iter()
            .find(|r| r.category == StreamCategory::DownloadAudit)
            .unwrap();
        assert!(
            dl.floor >= Duration::days(90),
            "DownloadAudit floor {:?} must be >= the ≥90d download-audit minimum",
            dl.floor
        );
        assert_eq!(dl.floor, Duration::days(90), "exact boundary value");
    }

    /// B13 — the TokenUse rule is AgeGated (rotated per-(token, date)
    /// audit stream, no terminal event — same shape as the
    /// AuthAttempts / DownloadAudit rules) and carries the supplied
    /// `api_token_used` credential-audit floor verbatim.
    #[test]
    fn contains_token_use_age_gated_rule_with_supplied_floor() {
        let rules = canonical_retention_rules(
            auth_floor(),
            lifecycle_floor(),
            download_audit_floor(),
            api_token_used_floor(),
        );
        let tu = rules
            .iter()
            .find(|r| r.category == StreamCategory::TokenUse)
            .expect("canonical set must register a TokenUse rule (B13)");
        assert_eq!(
            tu.mode,
            SealMode::AgeGated,
            "token-use streams have no terminal — AgeGated"
        );
        assert_eq!(
            tu.floor,
            api_token_used_floor(),
            "the ≥36mo api_token_used floor must be threaded verbatim"
        );
    }

    /// Boundary: the registered TokenUse floor is at-or-above
    /// the ≥36mo (1080d) credential-audit minimum.
    /// Pinning this surfaces a policy change at review time (the same
    /// discipline as the auth ≥6mo / download ≥90d boundary tests).
    #[test]
    fn token_use_floor_is_at_or_above_the_36mo_minimum() {
        let rules = canonical_retention_rules(
            auth_floor(),
            lifecycle_floor(),
            download_audit_floor(),
            Duration::days(1080),
        );
        let tu = rules
            .iter()
            .find(|r| r.category == StreamCategory::TokenUse)
            .unwrap();
        assert!(
            tu.floor >= Duration::days(1080),
            "TokenUse floor {:?} must be >= the ≥36mo (1080d) credential-audit minimum",
            tu.floor
        );
        assert_eq!(tu.floor, Duration::days(1080), "exact boundary value");
    }

    #[test]
    fn builder_is_pure_and_deterministic_for_given_durations() {
        // Same Durations in → byte-identical Vec out (no ordering or
        // value drift). Pure fn: no I/O, no global state.
        let a = canonical_retention_rules(
            auth_floor(),
            lifecycle_floor(),
            download_audit_floor(),
            api_token_used_floor(),
        );
        let b = canonical_retention_rules(
            auth_floor(),
            lifecycle_floor(),
            download_audit_floor(),
            api_token_used_floor(),
        );
        assert_eq!(a, b, "builder must be deterministic for given Durations");
    }

    #[test]
    fn builder_threads_distinct_floors_independently() {
        // Four distinct Durations must flow through 1:1 — proves no
        // accidental cross-wiring of the four floor params (B12 added
        // the third, B13 added the fourth).
        let auth = Duration::days(200);
        let lifecycle = Duration::days(900);
        let download = Duration::days(95);
        let token_use = Duration::days(1100);
        let rules = canonical_retention_rules(auth, lifecycle, download, token_use);
        let auth_rule = rules
            .iter()
            .find(|r| r.category == StreamCategory::AuthAttempts)
            .unwrap();
        let artifact_rule = rules
            .iter()
            .find(|r| r.category == StreamCategory::Artifact)
            .unwrap();
        let download_rule = rules
            .iter()
            .find(|r| r.category == StreamCategory::DownloadAudit)
            .unwrap();
        let token_use_rule = rules
            .iter()
            .find(|r| r.category == StreamCategory::TokenUse)
            .unwrap();
        assert_eq!(auth_rule.floor, auth);
        assert_eq!(artifact_rule.floor, lifecycle);
        assert_eq!(download_rule.floor, download);
        assert_eq!(token_use_rule.floor, token_use);
        assert_ne!(
            auth_rule.floor, artifact_rule.floor,
            "the floor params must not be cross-wired"
        );
        assert_ne!(
            download_rule.floor, auth_rule.floor,
            "the download-audit floor must not be cross-wired with auth"
        );
        assert_ne!(
            download_rule.floor, artifact_rule.floor,
            "the download-audit floor must not be cross-wired with lifecycle"
        );
        assert_ne!(
            token_use_rule.floor, download_rule.floor,
            "the token-use floor must not be cross-wired with download-audit"
        );
        assert_ne!(
            token_use_rule.floor, artifact_rule.floor,
            "the token-use floor must not be cross-wired with lifecycle"
        );
        assert_ne!(
            token_use_rule.floor, auth_rule.floor,
            "the token-use floor must not be cross-wired with auth"
        );
    }

    #[tokio::test]
    async fn canonical_auth_rule_drives_b5_age_gated_seal_at_the_supplied_floor() {
        // End-to-end through the mock harness: an auth-{date} stream
        // whose oldest event is JUST PAST the ≥6mo floor is sealed; one
        // JUST INSIDE the floor is NOT. `now` is pinned; the boundary
        // matches the existing AgeGated boundary tests exactly.
        let date = chrono::NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let sid = auth_stream(date);
        // Floor in seconds-comparable units so the C-1 comparison is
        // exact against pinned `now`/`first_event_at` (the production
        // builder threads a real `Duration`; here we feed a
        // pinned-comparable one to keep the boundary tight).
        let floor = floor_secs(100);
        let rules = canonical_retention_rules(
            floor,
            floor_secs(999_999),
            floor_secs(999_999),
            floor_secs(999_999),
        );

        // Just past: now - first == floor → elapsed >= floor → sealed.
        let h = build(
            MockReader::new().with(vec![candidate(
                sid.clone(),
                StreamCategory::AuthAttempts,
                ts(9_900),
                "AuthenticationAttempted",
            )]),
            MockEventStore::new().seed_stream(&sid, vec![auth_persisted(sid.parse().unwrap(), 0)]),
            rules.clone(),
            StreamRetentionModeRef::Delete,
        );
        let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
        assert_eq!(
            s.deleted, 1,
            "auth stream exactly at the ≥6mo floor must seal via the canonical AgeGated rule"
        );
        assert_eq!(s.skipped_floor_not_elapsed, 0);
        assert_eq!(h.store.deleted_streams(), vec![sid.clone()]);
    }

    #[tokio::test]
    async fn canonical_auth_rule_does_not_seal_just_inside_the_floor() {
        let date = chrono::NaiveDate::from_ymd_opt(2026, 7, 1).unwrap();
        let sid = auth_stream(date);
        let floor = floor_secs(100);
        let rules = canonical_retention_rules(
            floor,
            floor_secs(999_999),
            floor_secs(999_999),
            floor_secs(999_999),
        );

        // Just inside: now - first == floor - 1 → NOT sealed.
        let h = build(
            MockReader::new().with(vec![candidate(
                sid.clone(),
                StreamCategory::AuthAttempts,
                ts(9_901),
                "AuthenticationAttempted",
            )]),
            MockEventStore::new().seed_stream(&sid, vec![auth_persisted(sid.parse().unwrap(), 0)]),
            rules,
            StreamRetentionModeRef::Delete,
        );
        let s = h.uc.archive_terminal_streams(ts(10_000)).await.unwrap();
        assert_eq!(
            s.deleted, 0,
            "auth stream one second short of the ≥6mo floor must NOT seal"
        );
        assert_eq!(s.skipped_floor_not_elapsed, 1);
        assert!(h.store.deleted_streams().is_empty());
    }
}
