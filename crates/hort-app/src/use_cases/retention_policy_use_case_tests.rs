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
}

impl MockEventStore {
    fn new() -> Self {
        Self {
            appended: Mutex::new(Vec::new()),
            next_results: Mutex::new(Vec::new()),
        }
    }
    fn push_append_error(&self, e: DomainError) {
        self.next_results.lock().unwrap().push(Err(e));
    }
    fn appended_batches(&self) -> Vec<AppendEvents> {
        self.appended.lock().unwrap().clone()
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
        _s: &StreamId,
        _f: ReadFrom,
        _m: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn read_category(
        &self,
        _c: StreamCategory,
        _f: SubscribeFrom,
        _m: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn delete_stream(&self, _s: StreamId) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async { unimplemented!("retention policy use case never deletes streams") })
    }
    fn archive_stream(&self, _s: StreamId, _t: &str) -> BoxFuture<'_, DomainResult<()>> {
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
    fn list_active(
        &self,
    ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::retention::RetentionPolicy>>> {
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

#[tokio::test]
async fn update_maps_append_conflict() {
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
        .expect_err("stale expected_version → Conflict");
    assert!(matches!(err, AppError::Domain(DomainError::Conflict(_))));
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
