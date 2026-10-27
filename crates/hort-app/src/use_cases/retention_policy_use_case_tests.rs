//! Tests for `RetentionPolicyUseCase` — 100% hort-app
//! coverage tier. Mock event store + projection port; mirrors the
//! `policy_use_case` test structure (append+upsert, the
//! append-then-upsert-staleness branch, conflict mapping, the
//! no-reactivation terminal-archive model).

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::Utc;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{ApiActor, DomainEvent, PersistedEvent, StreamCategory, StreamId};
use hort_domain::ports::event_store::{
    AppendEvents, AppendResult, EventStore, ExpectedVersion, ReadFrom, SubscribeFrom,
};
use hort_domain::ports::retention_policy_projection_repository::{
    RetentionPolicyProjectionRepository, RetentionPolicyRow,
};
use hort_domain::ports::BoxFuture;
use hort_domain::retention::{PolicyPredicate, RetentionPolicyEvent, RetentionScope};
use uuid::Uuid;

use super::*;

fn gitops_actor() -> Actor {
    Actor::Api(ApiActor {
        user_id: Uuid::new_v4(),
    })
}

// -- MockEventStore ---------------------------------------------------------

struct MockEventStore {
    appended: Mutex<Vec<AppendEvents>>,
    next_results: Mutex<Vec<Result<AppendResult, DomainError>>>,
    /// Pre-seeded streams, keyed by `StreamId`. Served by `read_stream`
    /// so the self-heal's re-base has a stream to fold.
    seeded_streams: Mutex<HashMap<StreamId, Vec<PersistedEvent>>>,
    /// When `Some`, the NEXT `read_stream` returns this error (consumed
    /// on fire) — the infrastructure failure the re-base must refuse on
    /// rather than guess past.
    next_read_error: Mutex<Option<DomainError>>,
}

impl MockEventStore {
    fn new() -> Self {
        Self {
            appended: Mutex::new(Vec::new()),
            next_results: Mutex::new(Vec::new()),
            seeded_streams: Mutex::new(HashMap::new()),
            next_read_error: Mutex::new(None),
        }
    }
    fn push_append_error(&self, e: DomainError) {
        self.next_results.lock().unwrap().push(Err(e));
    }
    fn push_append_result(&self, r: AppendResult) {
        self.next_results.lock().unwrap().push(Ok(r));
    }
    fn appended_batches(&self) -> Vec<AppendEvents> {
        self.appended.lock().unwrap().clone()
    }
    fn fail_next_read_stream(&self, e: DomainError) {
        *self.next_read_error.lock().unwrap() = Some(e);
    }

    /// Seed the retention stream a real producer would have written for
    /// `row`: the opening `Created`, plus `extra` events after it. Returns
    /// the tail `stream_position`.
    ///
    /// Every event is run through `validate()` first, for the reason the
    /// workspace's round-tripping doubles do: the production event store
    /// validates on append, so an event this seeding accepted and the
    /// adapter would reject is an event no producer can write, and a test
    /// standing on one proves a behaviour production cannot show.
    fn seed_retention_stream(
        &self,
        row: &RetentionPolicyRow,
        extra: Vec<RetentionPolicyEvent>,
    ) -> u64 {
        let created = RetentionPolicyEvent::Created {
            id: row.policy_id,
            name: row.name.clone(),
            predicate: row.predicate.clone(),
            scope: row.scope.clone(),
            created_at: row.created_at,
        };
        let stream_id = StreamId::retention_policy(row.policy_id);
        let persisted: Vec<PersistedEvent> = std::iter::once(created)
            .chain(extra)
            .enumerate()
            .map(|(i, event)| {
                event
                    .validate()
                    .expect("seeded events must be ones a producer could append");
                PersistedEvent {
                    event_id: Uuid::new_v4(),
                    stream_id: stream_id.clone(),
                    stream_position: i as u64,
                    global_position: i as u64,
                    event: DomainEvent::RetentionPolicyChanged(event),
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor: gitops_actor(),
                    event_version: 1,
                    stored_at: row.created_at,
                }
            })
            .collect();
        let tail = persisted.len() as u64 - 1;
        self.seeded_streams
            .lock()
            .unwrap()
            .insert(stream_id, persisted);
        tail
    }
}

impl EventStore for MockEventStore {
    fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
        let count = batch.events.len() as u64;
        let next = self.next_results.lock().unwrap().pop();
        self.appended.lock().unwrap().push(batch);
        Box::pin(async move {
            match next {
                Some(Ok(r)) => Ok(r),
                Some(Err(e)) => Err(e),
                None => Ok(AppendResult {
                    stream_position: count.saturating_sub(1),
                    global_positions: (0..count).collect(),
                }),
            }
        })
    }
    fn read_stream(
        &self,
        s: &StreamId,
        _f: ReadFrom,
        _m: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
        if let Some(e) = self.next_read_error.lock().unwrap().take() {
            return Box::pin(async move { Err(e) });
        }
        let found = self
            .seeded_streams
            .lock()
            .unwrap()
            .get(s)
            .cloned()
            .unwrap_or_default();
        Box::pin(async move { Ok(found) })
    }
    fn read_category(
        &self,
        _c: StreamCategory,
        _f: SubscribeFrom,
        _m: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn delete_stream(
        &self,
        _s: StreamId,
        _authority: hort_domain::ports::event_store::SealAuthority,
    ) -> BoxFuture<'_, DomainResult<hort_domain::ports::event_store::SealOutcome>> {
        Box::pin(async { unimplemented!("retention policy use case never deletes streams") })
    }
    fn archive_stream(
        &self,
        _s: StreamId,
        _t: &str,
        _authority: hort_domain::ports::event_store::SealAuthority,
    ) -> BoxFuture<'_, DomainResult<hort_domain::ports::event_store::SealOutcome>> {
        Box::pin(async { unimplemented!("retention policy use case never archives streams") })
    }
}

// -- MockRetentionPolicyProjections -----------------------------------------

struct MockProjections {
    rows: Mutex<HashMap<Uuid, RetentionPolicyRow>>,
    upserts: Mutex<Vec<RetentionPolicyRow>>,
    next_upsert_error: Mutex<Option<DomainError>>,
}

impl MockProjections {
    fn new() -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
            upserts: Mutex::new(Vec::new()),
            next_upsert_error: Mutex::new(None),
        }
    }
    fn insert(&self, r: RetentionPolicyRow) {
        self.rows.lock().unwrap().insert(r.policy_id, r);
    }
    fn fail_next_upsert(&self, e: DomainError) {
        *self.next_upsert_error.lock().unwrap() = Some(e);
    }
    fn upserts(&self) -> Vec<RetentionPolicyRow> {
        self.upserts.lock().unwrap().clone()
    }
}

impl RetentionPolicyProjectionRepository for MockProjections {
    fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicy>>> {
        let v: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .values()
            .filter(|r| !r.archived)
            .cloned()
            .map(RetentionPolicyRow::into_policy)
            .collect();
        Box::pin(async move { Ok(v) })
    }
    fn find_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>> {
        let found = self
            .rows
            .lock()
            .unwrap()
            .values()
            .find(|r| r.name == name && !r.archived)
            .cloned();
        Box::pin(async move { Ok(found) })
    }
    fn find_by_name_including_archived(
        &self,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>> {
        let found = self
            .rows
            .lock()
            .unwrap()
            .values()
            .find(|r| r.name == name)
            .cloned();
        Box::pin(async move { Ok(found) })
    }
    fn list_active_rows(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicyRow>>> {
        let v: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .values()
            .filter(|r| !r.archived)
            .cloned()
            .collect();
        Box::pin(async move { Ok(v) })
    }
    fn upsert(&self, row: &RetentionPolicyRow) -> BoxFuture<'_, DomainResult<()>> {
        if let Some(e) = self.next_upsert_error.lock().unwrap().take() {
            return Box::pin(async move { Err(e) });
        }
        self.upserts.lock().unwrap().push(row.clone());
        self.rows.lock().unwrap().insert(row.policy_id, row.clone());
        Box::pin(async { Ok(()) })
    }
}

fn make_use_case() -> (
    RetentionPolicyUseCase,
    Arc<MockEventStore>,
    Arc<MockProjections>,
) {
    let events = Arc::new(MockEventStore::new());
    let projections = Arc::new(MockProjections::new());
    let uc = RetentionPolicyUseCase::new(
        crate::event_store_publisher::wrap_for_test(events.clone()),
        projections.clone(),
    );
    (uc, events, projections)
}

fn sample_row(id: Uuid, name: &str, version: u64, archived: bool) -> RetentionPolicyRow {
    RetentionPolicyRow {
        policy_id: id,
        name: name.into(),
        predicate: PolicyPredicate::AgeExceeds(60),
        scope: RetentionScope::AllRepos,
        archived,
        stream_version: version,
        last_evaluated_at: None,
        last_matched_count: 0,
        last_expired_count: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// ===========================================================================
// create_policy
// ===========================================================================

#[tokio::test]
async fn create_appends_created_event_and_upserts_projection() {
    let (uc, events, projections) = make_use_case();
    let cmd = CreateRetentionPolicyCommand {
        name: "retain-30d".into(),
        predicate: PolicyPredicate::AgeExceeds(2_592_000),
        scope: RetentionScope::AllRepos,
    };
    let id = uc.create_policy(cmd, gitops_actor()).await.expect("create");

    let batches = events.appended_batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].expected_version, ExpectedVersion::NoStream);
    assert!(matches!(
        &batches[0].events[0].event,
        DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Created { .. })
    ));
    assert_eq!(
        batches[0].stream_id.category,
        StreamCategory::RetentionPolicy
    );
    assert_eq!(batches[0].stream_id.entity_id, id);

    let ups = projections.upserts();
    assert_eq!(ups.len(), 1);
    assert_eq!(ups[0].policy_id, id);
    assert_eq!(ups[0].predicate, PolicyPredicate::AgeExceeds(2_592_000));
    assert!(!ups[0].archived);
}

#[tokio::test]
async fn create_rejects_duplicate_active_name_with_conflict() {
    let (uc, events, projections) = make_use_case();
    projections.insert(sample_row(Uuid::new_v4(), "dup", 0, false));
    let cmd = CreateRetentionPolicyCommand {
        name: "dup".into(),
        predicate: PolicyPredicate::AgeExceeds(60),
        scope: RetentionScope::AllRepos,
    };
    let err = uc
        .create_policy(cmd, gitops_actor())
        .await
        .expect_err("duplicate name must be rejected");
    assert!(matches!(err, AppError::Domain(DomainError::Conflict(_))));
    // The pre-check fired BEFORE the append — no stream position burned.
    assert_eq!(events.appended_batches().len(), 0);
}

#[tokio::test]
async fn create_propagates_upsert_failure_after_append() {
    let (uc, _events, projections) = make_use_case();
    projections.fail_next_upsert(DomainError::Invariant("db down".into()));
    let cmd = CreateRetentionPolicyCommand {
        name: "x".into(),
        predicate: PolicyPredicate::AgeExceeds(60),
        scope: RetentionScope::AllRepos,
    };
    let err = uc
        .create_policy(cmd, gitops_actor())
        .await
        .expect_err("upsert failure after append must surface");
    assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
}

#[tokio::test]
async fn create_rejects_malformed_predicate_via_domain_validate() {
    let (uc, events, _projections) = make_use_case();
    let cmd = CreateRetentionPolicyCommand {
        name: "bad".into(),
        // B1 rejects a 0s TTL.
        predicate: PolicyPredicate::AgeExceeds(0),
        scope: RetentionScope::AllRepos,
    };
    let err = uc
        .create_policy(cmd, gitops_actor())
        .await
        .expect_err("0s TTL must be domain-rejected");
    assert!(matches!(err, AppError::Domain(DomainError::Validation(_))));
    // Rejected before the append.
    assert_eq!(events.appended_batches().len(), 0);
}

// ===========================================================================
// update_policy
// ===========================================================================

#[tokio::test]
async fn update_appends_updated_event_with_exact_version_and_upserts() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    projections.insert(sample_row(id, "p", 3, false));
    let cmd = UpdateRetentionPolicyCommand {
        policy_id: id,
        predicate: PolicyPredicate::AgeExceeds(7_200),
        scope: RetentionScope::IngestSource(hort_domain::events::IngestSource::Proxied),
    };
    uc.update_policy(cmd, gitops_actor()).await.expect("update");

    let batches = events.appended_batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].expected_version, ExpectedVersion::Exact(3));
    assert!(matches!(
        &batches[0].events[0].event,
        DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Updated { .. })
    ));
    let ups = projections.upserts();
    assert_eq!(
        ups.last().unwrap().predicate,
        PolicyPredicate::AgeExceeds(7_200)
    );
}

#[tokio::test]
async fn update_same_value_is_idempotent_no_append() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    projections.insert(sample_row(id, "p", 1, false)); // AgeExceeds(60), AllRepos
    let cmd = UpdateRetentionPolicyCommand {
        policy_id: id,
        predicate: PolicyPredicate::AgeExceeds(60),
        scope: RetentionScope::AllRepos,
    };
    uc.update_policy(cmd, gitops_actor())
        .await
        .expect("idempotent no-op");
    assert_eq!(
        events.appended_batches().len(),
        0,
        "same-value update must not append"
    );
    assert_eq!(projections.upserts().len(), 0);
}

#[tokio::test]
async fn update_unknown_policy_is_not_found() {
    let (uc, _events, _projections) = make_use_case();
    let err = uc
        .update_policy(
            UpdateRetentionPolicyCommand {
                policy_id: Uuid::new_v4(),
                predicate: PolicyPredicate::AgeExceeds(60),
                scope: RetentionScope::AllRepos,
            },
            gitops_actor(),
        )
        .await
        .expect_err("unknown id");
    assert!(matches!(
        err,
        AppError::Domain(DomainError::NotFound { .. })
    ));
}

#[tokio::test]
async fn update_archived_policy_is_rejected() {
    let (uc, _events, projections) = make_use_case();
    let id = Uuid::new_v4();
    // Archived rows are not in list_active_rows → resolves as NotFound
    // (the apply pipeline never updates an archived policy; B1
    // terminal-archive). Assert the (defensive) NotFound here.
    projections.insert(sample_row(id, "p", 1, true));
    let err = uc
        .update_policy(
            UpdateRetentionPolicyCommand {
                policy_id: id,
                predicate: PolicyPredicate::AgeExceeds(99),
                scope: RetentionScope::AllRepos,
            },
            gitops_actor(),
        )
        .await
        .expect_err("archived policy not updatable");
    assert!(matches!(
        err,
        AppError::Domain(DomainError::NotFound { .. })
    ));
}

/// The stale-row repair at the retention `update_policy` site: the row is
/// behind its stream, the first append is refused, and the retry appends
/// at the version the stream reports.
#[tokio::test]
async fn update_heals_a_stale_row_and_appends_at_the_stream_version() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    let stale = sample_row(id, "p", 0, false);
    let tail = events.seed_retention_stream(
        &stale,
        vec![RetentionPolicyEvent::Updated {
            id,
            predicate: PolicyPredicate::AgeExceeds(99),
            scope: RetentionScope::AllRepos,
            updated_at: stale.created_at,
        }],
    );
    projections.insert(stale);
    // LIFO: the result for the SECOND append is pushed first.
    events.push_append_result(AppendResult {
        stream_position: 2,
        global_positions: vec![2],
    });
    events.push_append_error(DomainError::Conflict("expected_version=0".into()));

    uc.update_policy(
        UpdateRetentionPolicyCommand {
            policy_id: id,
            predicate: PolicyPredicate::AgeExceeds(123),
            scope: RetentionScope::AllRepos,
        },
        gitops_actor(),
    )
    .await
    .expect("heals");

    let batches = events.appended_batches();
    assert_eq!(batches.len(), 2, "one refused attempt, one that lands");
    assert_eq!(batches[0].expected_version, ExpectedVersion::Exact(0));
    assert_eq!(
        batches[1].expected_version,
        ExpectedVersion::Exact(tail),
        "the retry must ask with the version the stream reports"
    );
    let last = projections.upserts().last().cloned().expect("an upsert");
    assert_eq!(last.predicate, PolicyPredicate::AgeExceeds(123));
    assert_eq!(last.stream_version, 2);
}

/// A conflict whose stream already states the update is an idempotent
/// success, and the stale row is repaired on the way out.
#[tokio::test]
async fn update_whose_stream_already_states_it_succeeds_and_repairs_the_row() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    let stale = sample_row(id, "p", 0, false);
    let tail = events.seed_retention_stream(
        &stale,
        vec![RetentionPolicyEvent::Updated {
            id,
            predicate: PolicyPredicate::AgeExceeds(123),
            scope: RetentionScope::AllRepos,
            updated_at: stale.created_at,
        }],
    );
    projections.insert(stale);
    events.push_append_error(DomainError::Conflict("expected_version=0".into()));

    uc.update_policy(
        UpdateRetentionPolicyCommand {
            policy_id: id,
            predicate: PolicyPredicate::AgeExceeds(123),
            scope: RetentionScope::AllRepos,
        },
        gitops_actor(),
    )
    .await
    .expect("idempotent");

    assert_eq!(
        events.appended_batches().len(),
        1,
        "the re-decide found the intent already satisfied"
    );
    let last = projections.upserts().last().cloned().expect("an upsert");
    assert_eq!(last.predicate, PolicyPredicate::AgeExceeds(123));
    assert_eq!(last.stream_version, tail);
}

/// A second refusal is a genuine concurrent writer — the second attempt's
/// expected version came off the stream — and surfaces as retryable-busy
/// (ADR 0060 (d)).
#[tokio::test]
async fn update_reports_a_genuine_concurrent_writer_as_contention() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    let row = sample_row(id, "p", 0, false);
    events.seed_retention_stream(&row, Vec::new());
    projections.insert(row);
    events.push_append_error(DomainError::Conflict("expected_version=0".into()));
    events.push_append_error(DomainError::Conflict("expected_version=0".into()));

    let err = uc
        .update_policy(
            UpdateRetentionPolicyCommand {
                policy_id: id,
                predicate: PolicyPredicate::AgeExceeds(123),
                scope: RetentionScope::AllRepos,
            },
            gitops_actor(),
        )
        .await
        .expect_err("a conflict surviving the re-base must propagate");
    assert!(
        matches!(err, AppError::Domain(DomainError::Contended(_))),
        "got {err:?}"
    );
    assert_eq!(
        events.appended_batches().len(),
        2,
        "bounded at two attempts"
    );
    assert!(projections.upserts().is_empty(), "nothing is written");
}

/// A concurrent archival the caller could not have seen: the row says
/// active, the stream says archived. B1's model is terminal-archive, so
/// the re-decide refuses rather than appending an `Updated` the replay
/// would itself reject on the next read.
#[tokio::test]
async fn update_refuses_when_the_stream_says_the_policy_was_archived() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    let stale = sample_row(id, "p", 0, false);
    events.seed_retention_stream(
        &stale,
        vec![RetentionPolicyEvent::Archived {
            id,
            by: Uuid::new_v4(),
            archived_at: stale.created_at,
        }],
    );
    projections.insert(stale);
    events.push_append_error(DomainError::Conflict("expected_version=0".into()));

    let err = uc
        .update_policy(
            UpdateRetentionPolicyCommand {
                policy_id: id,
                predicate: PolicyPredicate::AgeExceeds(123),
                scope: RetentionScope::AllRepos,
            },
            gitops_actor(),
        )
        .await
        .expect_err("an archived policy must refuse the update");
    match err {
        AppError::Domain(DomainError::Validation(msg)) => {
            assert!(msg.contains("archived"), "got: {msg}");
        }
        other => panic!("expected Validation, got {other:?}"),
    }
    assert_eq!(events.appended_batches().len(), 1);
    assert!(projections.upserts().is_empty(), "nothing is rewritten");
}

/// Fail-closed: a stream that cannot be read rewrites nothing.
#[tokio::test]
async fn update_refuses_and_rewrites_nothing_when_the_stream_cannot_be_read() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    let row = sample_row(id, "p", 5, false);
    events.seed_retention_stream(&row, Vec::new());
    projections.insert(row);
    events.push_append_error(DomainError::Conflict("expected_version=5".into()));
    events.fail_next_read_stream(DomainError::Invariant("event store down".into()));

    let err = uc
        .update_policy(
            UpdateRetentionPolicyCommand {
                policy_id: id,
                predicate: PolicyPredicate::AgeExceeds(123),
                scope: RetentionScope::AllRepos,
            },
            gitops_actor(),
        )
        .await
        .expect_err("an unreadable stream must refuse");
    assert!(err.to_string().contains("event store down"), "got: {err}");
    assert_eq!(events.appended_batches().len(), 1);
    assert!(projections.upserts().is_empty(), "nothing is rewritten");
}

/// Fail-closed: a stream the replay refuses rewrites nothing. An empty
/// stream is the shape a conflict on a policy whose events are gone takes.
#[tokio::test]
async fn update_refuses_and_rewrites_nothing_when_the_stream_cannot_be_replayed() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    projections.insert(sample_row(id, "p", 5, false));
    events.push_append_error(DomainError::Conflict("expected_version=5".into()));

    let err = uc
        .update_policy(
            UpdateRetentionPolicyCommand {
                policy_id: id,
                predicate: PolicyPredicate::AgeExceeds(123),
                scope: RetentionScope::AllRepos,
            },
            gitops_actor(),
        )
        .await
        .expect_err("an unreplayable stream must refuse");
    assert!(
        matches!(err, AppError::Domain(DomainError::Invariant(_))),
        "RetentionPolicy::project refuses an empty stream, got {err:?}"
    );
    assert!(projections.upserts().is_empty(), "nothing is rewritten");
}

/// An event on the retention stream that is not a
/// `RetentionPolicyChanged` refuses the replay rather than being skipped:
/// a row derived from a stream the replay cannot read in full would be
/// missing whatever that event said.
#[tokio::test]
async fn update_refuses_a_stream_carrying_a_foreign_event() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    let row = sample_row(id, "p", 0, false);
    events.seed_retention_stream(&row, Vec::new());
    // Append a foreign event onto the seeded stream.
    {
        let stream_id = StreamId::retention_policy(id);
        let mut streams = events.seeded_streams.lock().unwrap();
        let stream = streams.get_mut(&stream_id).expect("seeded");
        stream.push(PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: stream_id.clone(),
            stream_position: 1,
            global_position: 1,
            event: DomainEvent::ArtifactQuarantined(hort_domain::events::ArtifactQuarantined {
                artifact_id: Uuid::new_v4(),
                quarantine_window_start: row.created_at,
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: gitops_actor(),
            event_version: 1,
            stored_at: row.created_at,
        });
    }
    projections.insert(row);
    events.push_append_error(DomainError::Conflict("expected_version=0".into()));

    let err = uc
        .update_policy(
            UpdateRetentionPolicyCommand {
                policy_id: id,
                predicate: PolicyPredicate::AgeExceeds(123),
                scope: RetentionScope::AllRepos,
            },
            gitops_actor(),
        )
        .await
        .expect_err("a foreign event must refuse the replay");
    match err {
        AppError::Domain(DomainError::Invariant(msg)) => assert!(
            msg.contains("ArtifactQuarantined"),
            "the refusal must name the foreign event: {msg}"
        ),
        other => panic!("expected Invariant, got {other:?}"),
    }
    assert!(projections.upserts().is_empty(), "nothing is rewritten");
}

/// The stale-row repair at the retention `archive_policy` site.
#[tokio::test]
async fn archive_heals_a_stale_row() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    let stale = sample_row(id, "p", 0, false);
    let tail = events.seed_retention_stream(
        &stale,
        vec![RetentionPolicyEvent::Updated {
            id,
            predicate: PolicyPredicate::AgeExceeds(99),
            scope: RetentionScope::AllRepos,
            updated_at: stale.created_at,
        }],
    );
    projections.insert(stale);
    events.push_append_error(DomainError::Conflict("expected_version=0".into()));

    uc.archive_policy(id, Uuid::new_v4(), gitops_actor())
        .await
        .expect("heals");

    let batches = events.appended_batches();
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[1].expected_version, ExpectedVersion::Exact(tail));
    let last = projections.upserts().last().cloned().expect("an upsert");
    assert!(last.archived);
    assert_eq!(
        last.predicate,
        PolicyPredicate::AgeExceeds(99),
        "the repaired row carries the predicate the stale row had missed"
    );
}

/// A stream that already says archived satisfies the intent: the call
/// succeeds and the stale row is repaired, rather than being answered with
/// a `Validation` error about a state the caller could not see.
#[tokio::test]
async fn archive_whose_stream_already_says_archived_succeeds_and_repairs_the_row() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    let stale = sample_row(id, "p", 0, false);
    let tail = events.seed_retention_stream(
        &stale,
        vec![RetentionPolicyEvent::Archived {
            id,
            by: Uuid::new_v4(),
            archived_at: stale.created_at,
        }],
    );
    projections.insert(stale);
    events.push_append_error(DomainError::Conflict("expected_version=0".into()));

    uc.archive_policy(id, Uuid::new_v4(), gitops_actor())
        .await
        .expect("idempotent");

    assert_eq!(
        events.appended_batches().len(),
        1,
        "a second Archived would be refused by the replay's terminal-archive \
         rule anyway, and would record an archival that did not happen"
    );
    let last = projections.upserts().last().cloned().expect("an upsert");
    assert!(last.archived);
    assert_eq!(last.stream_version, tail);
}

#[tokio::test]
async fn archive_refuses_and_rewrites_nothing_when_the_stream_cannot_be_read() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    let row = sample_row(id, "p", 5, false);
    events.seed_retention_stream(&row, Vec::new());
    projections.insert(row);
    events.push_append_error(DomainError::Conflict("expected_version=5".into()));
    events.fail_next_read_stream(DomainError::Invariant("event store down".into()));

    let err = uc
        .archive_policy(id, Uuid::new_v4(), gitops_actor())
        .await
        .expect_err("an unreadable stream must refuse");
    assert!(err.to_string().contains("event store down"), "got: {err}");
    assert!(projections.upserts().is_empty(), "nothing is rewritten");
}

#[tokio::test]
async fn update_propagates_upsert_failure_after_append() {
    let (uc, _events, projections) = make_use_case();
    let id = Uuid::new_v4();
    projections.insert(sample_row(id, "p", 2, false));
    projections.fail_next_upsert(DomainError::Invariant("db down".into()));
    let err = uc
        .update_policy(
            UpdateRetentionPolicyCommand {
                policy_id: id,
                predicate: PolicyPredicate::AgeExceeds(456),
                scope: RetentionScope::AllRepos,
            },
            gitops_actor(),
        )
        .await
        .expect_err("post-append upsert failure surfaces");
    assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
}

// ===========================================================================
// archive_policy
// ===========================================================================

#[tokio::test]
async fn archive_appends_archived_event_and_marks_projection() {
    let (uc, events, projections) = make_use_case();
    let id = Uuid::new_v4();
    let by = Uuid::new_v4();
    projections.insert(sample_row(id, "p", 4, false));
    uc.archive_policy(id, by, gitops_actor())
        .await
        .expect("archive");
    let batches = events.appended_batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].expected_version, ExpectedVersion::Exact(4));
    match &batches[0].events[0].event {
        DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Archived {
            id: eid,
            by: eby,
            ..
        }) => {
            assert_eq!(*eid, id);
            assert_eq!(*eby, by);
        }
        other => panic!("expected Archived, got {other:?}"),
    }
    assert!(projections.upserts().last().unwrap().archived);
}

#[tokio::test]
async fn archive_already_archived_is_not_found_defensive() {
    let (uc, _events, projections) = make_use_case();
    let id = Uuid::new_v4();
    projections.insert(sample_row(id, "p", 1, true));
    let err = uc
        .archive_policy(id, Uuid::new_v4(), gitops_actor())
        .await
        .expect_err("archived policy not in active set");
    assert!(matches!(
        err,
        AppError::Domain(DomainError::NotFound { .. })
    ));
}

#[tokio::test]
async fn archive_unknown_policy_is_not_found() {
    let (uc, _events, _projections) = make_use_case();
    let err = uc
        .archive_policy(Uuid::new_v4(), Uuid::new_v4(), gitops_actor())
        .await
        .expect_err("unknown id");
    assert!(matches!(
        err,
        AppError::Domain(DomainError::NotFound { .. })
    ));
}

#[tokio::test]
async fn archive_propagates_upsert_failure_after_append() {
    let (uc, _events, projections) = make_use_case();
    let id = Uuid::new_v4();
    projections.insert(sample_row(id, "p", 0, false));
    projections.fail_next_upsert(DomainError::Invariant("db down".into()));
    let err = uc
        .archive_policy(id, Uuid::new_v4(), gitops_actor())
        .await
        .expect_err("post-append upsert failure surfaces");
    assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
}
