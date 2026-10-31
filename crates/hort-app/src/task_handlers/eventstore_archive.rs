//! `EventStoreArchiveHandler`.
//!
//! The `kind = "eventstore-archive"` TaskHandler. Triggered by the k8s
//! CronJob hitting `POST /api/v1/admin/tasks/eventstore-archive`
//! (the route lives in `hort-http-admin-tasks`).
//! Default schedule `0 5 * * 0` (weekly). Thin orchestration over
//! [`EventStoreRetentionUseCase::archive_terminal_streams`] — the
//! audit-retention stream sweep (seal terminal / age-gated streams
//! once their retention floor has elapsed, via the `seal_and_remove`
//! `StreamSealed`-tombstone chokepoint).
//!
//! When `HORT_RETENTION_DATABASE_URL` is unset the
//! composition root wires this use case's `EventStorePublisher` over
//! the `hort_app_role` pool — every `delete_stream` then fails fail-safe
//! via the still-active `events_immutable` trigger (the
//! seal-tombstone-first transaction rolls back, zero rows removed). A
//! per-stream failure is recorded in the summary and the sweep
//! continues; only `list_terminal_candidates` failing aborts the sweep
//! (→ retryable `TaskOutcome::fail`).
//!
//! ## Anchoring the seals this sweep made
//!
//! A `StreamSealed` tombstone is tamper-evident only once a checkpoint
//! that post-dates it anchors its head; until then the offline verifier
//! records `AnchorBreak::SealUnanchored`
//! (`hort_domain::events::chain`). This handler is where that
//! anchoring is driven, through the optional
//! [`CheckpointEmissionHook`]:
//!
//! * **After** the sweep, never between a seal and its delete. The
//!   adapter's `seal_and_remove` appends the tombstone and runs the
//!   `DELETE` inside one transaction (ADR 0020), and the emitter reads
//!   a `REPEATABLE READ` snapshot on its own connection — so no
//!   instant exists at which an independent reader could see the
//!   tombstone but not the delete. The residual unanchored window is
//!   therefore the sweep's own duration, after which every seal it made
//!   is anchored.
//! * **Exactly once per sweep**, not once per stream: each emission is
//!   an Ed25519 sign plus an S3 Object-Lock write, and one sweep can
//!   seal many streams.
//! * **Only when the sweep actually sealed something**
//!   ([`RetentionArchiveSummary::sealed_stream_ids`] non-empty). A
//!   sweep that sealed nothing has nothing to anchor, and an
//!   unconditional emission would spend an anchor write per tick for no
//!   statement.
//! * **`None` is a correct wiring, not a degradation.** The checkpoint
//!   handler the hook wraps is registered only where
//!   `anchoring::checkpoint_emission_status` is `Enabled` — an S3
//!   backend with both operator-provisioned anchor keys. Where no
//!   anchor is expected, a missing checkpoint is not a failure
//!   (ADR 0057), so the hook is simply absent and the sweep reports
//!   `Completed`.
//!
//! A failed emission is reported, never swallowed: the sweep's seals
//! are already committed and cannot be undone, so the only honest
//! answer is a non-success outcome naming the sealed-but-unanchored
//! streams. See the call site for why that is
//! `TaskOutcome::Failed { retry: false }`.

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;

use hort_domain::error::DomainResult;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use crate::task_handlers::eventstore_checkpoint::CheckpointEmissionHook;
use crate::use_cases::eventstore_retention_use_case::EventStoreRetentionUseCase;

/// [`TaskHandler`] for the periodic audit-retention stream sweep.
pub struct EventStoreArchiveHandler {
    retention: Arc<EventStoreRetentionUseCase>,
    /// Anchors the seals one sweep made, once, after the sweep. `None`
    /// where checkpoint emission is off — see the module docs.
    checkpoint_hook: Option<Arc<dyn CheckpointEmissionHook>>,
}

impl EventStoreArchiveHandler {
    /// Construct the handler.
    ///
    /// * `retention` — the audit-retention stream sweep.
    /// * `checkpoint_hook` — anchors this sweep's seals once the sweep
    ///   is done. `Some` only where the composition root also
    ///   registered the `eventstore-checkpoint` handler, so the hook
    ///   and the handler cannot drift apart; `None` is a correct,
    ///   silent skip (ADR 0057 — where no anchor is expected a missing
    ///   checkpoint is not a failure).
    pub fn new(
        retention: Arc<EventStoreRetentionUseCase>,
        checkpoint_hook: Option<Arc<dyn CheckpointEmissionHook>>,
    ) -> Self {
        Self {
            retention,
            checkpoint_hook,
        }
    }
}

impl TaskHandler for EventStoreArchiveHandler {
    fn kind(&self) -> &'static str {
        "eventstore-archive"
    }

    #[tracing::instrument(skip(self))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let now = Utc::now();
            match self.retention.archive_terminal_streams(now).await {
                Ok(s) => {
                    tracing::info!(
                        candidates = s.candidates_visited,
                        archived = s.archived,
                        deleted = s.deleted,
                        skipped_non_terminal = s.skipped_non_terminal,
                        skipped_floor_not_elapsed = s.skipped_floor_not_elapsed,
                        skipped_meta_stream = s.skipped_meta_stream,
                        skipped_already_sealed = s.skipped_already_sealed,
                        skipped_unregistered_category = s.skipped_unregistered_category,
                        skipped_stream_changed = s.skipped_stream_changed,
                        errors = s.errors,
                        "eventstore-archive sweep complete"
                    );

                    // Anchor this sweep's seals: one emission for the
                    // whole pass, after the seals have committed, and
                    // only if the pass sealed something. The adapter's
                    // `seal_and_remove` appends the `StreamSealed`
                    // tombstone and deletes the rows in one transaction
                    // (ADR 0020) while the emitter reads its own
                    // `REPEATABLE READ` snapshot, so there is no instant
                    // between the two for an emission to occupy; the
                    // unanchored window is this sweep's duration.
                    if let Some(hook) = &self.checkpoint_hook {
                        if !s.sealed_stream_ids.is_empty() {
                            if let Err(e) = hook.emit_checkpoint_now().await {
                                // The rows are gone and cannot be
                                // un-deleted, so this cannot abort
                                // anything — but it must not read as a
                                // clean sweep either. The next scheduled
                                // `eventstore-checkpoint` tick anchors
                                // these seals regardless (a checkpoint
                                // binds the `StreamSealed` records it
                                // finds on the audit-meta stream, which
                                // is never deleted), so the cost is
                                // visibility and latency, not
                                // durability.
                                //
                                // `retry: false`: re-running this sweep
                                // cannot anchor what the failed run
                                // sealed — those streams are gone from
                                // the candidate set, so the re-run seals
                                // nothing, skips the emission and
                                // reports `Completed`, erasing the only
                                // signal the operator had. The
                                // persistent `failed` jobs row is the
                                // point.
                                tracing::error!(
                                    error = %e,
                                    sealed_stream_ids = %s.sealed_stream_ids.join(","),
                                    sealed_count = s.sealed_stream_ids.len(),
                                    "eventstore-archive sealed streams but could not anchor \
                                     them: the checkpoint emission failed, so these \
                                     StreamSealed tombstones are unanchored until the next \
                                     eventstore-checkpoint tick, and verify-event-chain \
                                     reports AnchorBreak::SealUnanchored for them until then"
                                );
                                return Ok(TaskOutcome::fail(
                                    format!(
                                        "eventstore-archive sealed {} stream(s) \
                                         (archived={}, deleted={}, errors={}) but the \
                                         anchoring checkpoint emission failed: {e}. \
                                         Sealed-but-unanchored: {}",
                                        s.sealed_stream_ids.len(),
                                        s.archived,
                                        s.deleted,
                                        s.errors,
                                        s.sealed_stream_ids.join(","),
                                    ),
                                    false,
                                ));
                            }
                        }
                    }

                    Ok(TaskOutcome::Completed {
                        result_summary: json!({
                            "candidates": s.candidates_visited,
                            "archived": s.archived,
                            "deleted": s.deleted,
                            "skipped_non_terminal": s.skipped_non_terminal,
                            "skipped_floor_not_elapsed": s.skipped_floor_not_elapsed,
                            "skipped_meta_stream": s.skipped_meta_stream,
                            "skipped_already_sealed": s.skipped_already_sealed,
                            "skipped_unregistered_category": s.skipped_unregistered_category,
                            "skipped_stream_changed": s.skipped_stream_changed,
                            "errors": s.errors,
                        }),
                    })
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "eventstore-archive: list_terminal_candidates failed — \
                         retry next tick (fail-safe: nothing sealed)"
                    );
                    Ok(TaskOutcome::fail(
                        format!("archive_terminal_streams failed: {e}"),
                        true,
                    ))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use chrono::{DateTime, Duration, Utc};
    use hort_domain::error::DomainError;
    use hort_domain::events::{
        system_actor, Actor, ApiActor, ArtifactPurged, DomainEvent, PersistedEvent, StreamCategory,
        StreamId,
    };
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::ports::terminal_stream_reader::{
        TerminalStreamCandidate, TerminalStreamReader,
    };
    use hort_domain::types::ContentHash;
    use uuid::Uuid;

    use crate::use_cases::eventstore_retention_use_case::{
        CategoryRetentionRule, SealMode, StreamRetentionModeRef,
    };
    use crate::use_cases::test_support::MockEventStore;

    const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    struct MockReader {
        candidates: Mutex<Vec<TerminalStreamCandidate>>,
        err: Mutex<Option<DomainError>>,
    }
    impl MockReader {
        fn empty() -> Self {
            Self {
                candidates: Mutex::new(Vec::new()),
                err: Mutex::new(None),
            }
        }
        fn with(candidates: Vec<TerminalStreamCandidate>) -> Self {
            Self {
                candidates: Mutex::new(candidates),
                err: Mutex::new(None),
            }
        }
        fn failing() -> Self {
            Self {
                candidates: Mutex::new(Vec::new()),
                err: Mutex::new(Some(DomainError::Invariant("boom".into()))),
            }
        }
    }
    impl TerminalStreamReader for MockReader {
        fn list_terminal_candidates(
            &self,
        ) -> BoxFuture<'_, DomainResult<Vec<TerminalStreamCandidate>>> {
            if let Some(e) = self.err.lock().unwrap().take() {
                return Box::pin(async move { Err(e) });
            }
            let v = self.candidates.lock().unwrap().clone();
            Box::pin(async move { Ok(v) })
        }
    }

    /// A [`CheckpointEmissionHook`] double.
    ///
    /// Each call records how many `delete_stream` calls the event store
    /// had already recorded at that moment. That is what pins the
    /// *ordering* half of the contract — a hook that sees the sweep's
    /// deletes already done was called after the seals committed, which
    /// counting calls alone cannot show.
    struct MockHook {
        store: Arc<MockEventStore>,
        deletes_observed_per_call: Mutex<Vec<usize>>,
        fail: bool,
    }
    impl MockHook {
        fn ok(store: Arc<MockEventStore>) -> Arc<Self> {
            Arc::new(Self {
                store,
                deletes_observed_per_call: Mutex::new(Vec::new()),
                fail: false,
            })
        }
        fn failing(store: Arc<MockEventStore>) -> Arc<Self> {
            Arc::new(Self {
                store,
                deletes_observed_per_call: Mutex::new(Vec::new()),
                fail: true,
            })
        }
        fn calls(&self) -> Vec<usize> {
            self.deletes_observed_per_call.lock().unwrap().clone()
        }
    }
    impl CheckpointEmissionHook for MockHook {
        fn emit_checkpoint_now(&self) -> BoxFuture<'_, DomainResult<()>> {
            self.deletes_observed_per_call
                .lock()
                .unwrap()
                .push(self.store.deleted_streams().len());
            let fail = self.fail;
            Box::pin(async move {
                if fail {
                    Err(DomainError::Invariant(
                        "anchor object store unreachable".into(),
                    ))
                } else {
                    Ok(())
                }
            })
        }
    }

    fn artifact_rule() -> CategoryRetentionRule {
        CategoryRetentionRule {
            category: StreamCategory::Artifact,
            floor: Duration::days(1),
            mode: SealMode::TerminalGated {
                terminal_event_type: "ArtifactPurged",
            },
        }
    }

    /// A candidate whose terminal proof will succeed and whose floor
    /// elapsed long ago. `first_event_at` is relative to the real clock
    /// because the handler reads `Utc::now()` itself.
    fn sealable(artifact_id: Uuid) -> TerminalStreamCandidate {
        TerminalStreamCandidate {
            stream_id: StreamId::artifact(artifact_id).to_string(),
            category: StreamCategory::Artifact,
            first_event_at: Utc::now() - Duration::days(1000),
            last_event_at: Utc::now() - Duration::days(1000),
            last_event_type: "ArtifactPurged".into(),
            last_stream_position: 3,
        }
    }

    /// Same shape, but the retention floor has not elapsed — the sweep
    /// skips it, so it seals nothing.
    fn floor_not_elapsed(artifact_id: Uuid) -> TerminalStreamCandidate {
        TerminalStreamCandidate {
            stream_id: StreamId::artifact(artifact_id).to_string(),
            category: StreamCategory::Artifact,
            first_event_at: Utc::now(),
            last_event_at: Utc::now(),
            last_event_type: "ArtifactPurged".into(),
            last_stream_position: 3,
        }
    }

    fn purged(artifact_id: Uuid) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(artifact_id),
            stream_position: 3,
            global_position: 4,
            event: DomainEvent::ArtifactPurged(ArtifactPurged {
                artifact_id,
                content_hash: HASH_A.parse::<ContentHash>().unwrap(),
                refs_remaining: 0,
                purged_at: DateTime::<Utc>::UNIX_EPOCH,
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: DateTime::<Utc>::UNIX_EPOCH,
        }
    }

    /// Seed one terminal (`ArtifactPurged`) tail per artifact so the
    /// `TerminalGated` proof read finds the category terminal.
    fn store_with_terminal_streams(artifact_ids: &[Uuid]) -> Arc<MockEventStore> {
        let store = Arc::new(MockEventStore::new());
        for id in artifact_ids {
            store.set_stream(&StreamId::artifact(*id), vec![purged(*id)]);
        }
        store
    }

    fn uc(reader: Arc<MockReader>) -> Arc<EventStoreRetentionUseCase> {
        Arc::new(EventStoreRetentionUseCase::new(
            reader,
            crate::event_store_publisher::wrap_for_test(Arc::new(MockEventStore::new())),
            Vec::new(),
            StreamRetentionModeRef::Delete,
        ))
    }

    /// The sweep wired over a seeded store and the artifact retention
    /// rule, so a candidate can actually reach the seal chokepoint.
    fn sealing_uc(
        reader: Arc<MockReader>,
        store: Arc<MockEventStore>,
    ) -> Arc<EventStoreRetentionUseCase> {
        Arc::new(EventStoreRetentionUseCase::new(
            reader,
            crate::event_store_publisher::wrap_for_test(store),
            vec![artifact_rule()],
            StreamRetentionModeRef::Delete,
        ))
    }

    fn ctx() -> TaskContext {
        use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: JobRow {
                id: Uuid::nil(),
                kind: "eventstore-archive".into(),
                status: JobStatus::Running,
                params: Some(serde_json::Value::Null),
                actor_id: None,
                priority: 0,
                trigger_source: "test".into(),
                attempts: 1,
                created_at: DateTime::<Utc>::UNIX_EPOCH,
                updated_at: DateTime::<Utc>::UNIX_EPOCH,
                completed_at: None,
                last_error: None,
                result_summary: None,
                kind_fields: KindFields::Other,
            },
        }
    }

    #[test]
    fn kind_is_eventstore_archive() {
        assert_eq!(
            EventStoreArchiveHandler::new(uc(Arc::new(MockReader::empty())), None).kind(),
            "eventstore-archive"
        );
    }

    #[tokio::test]
    async fn empty_candidates_completes_with_zeroed_summary() {
        let h = EventStoreArchiveHandler::new(uc(Arc::new(MockReader::empty())), None);
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidates"], 0);
                assert_eq!(result_summary["archived"], 0);
                assert_eq!(result_summary["deleted"], 0);
                assert_eq!(result_summary["errors"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reader_error_returns_failed_retry() {
        let h = EventStoreArchiveHandler::new(uc(Arc::new(MockReader::failing())), None);
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "list_terminal_candidates failure must retry");
                assert!(reason.contains("archive_terminal_streams"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // ---- post-sweep checkpoint emission --------------------------------

    #[tokio::test]
    async fn hook_is_emitted_exactly_once_after_a_sweep_that_sealed() {
        // Two sealable streams. Each emission is a sign plus an S3
        // Object-Lock write, so the sweep emits once for the pass, not
        // once per stream.
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let store = store_with_terminal_streams(&[a, b]);
        let hook = MockHook::ok(store.clone());
        let h = EventStoreArchiveHandler::new(
            sealing_uc(
                Arc::new(MockReader::with(vec![sealable(a), sealable(b)])),
                store.clone(),
            ),
            Some(hook.clone()),
        );

        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["deleted"], 2);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(
            hook.calls(),
            vec![2],
            "exactly one emission, and it saw both seals already committed — \
             one emission per sweep, after the seals, never one per stream"
        );
        assert_eq!(store.deleted_streams().len(), 2);
    }

    #[tokio::test]
    async fn hook_is_not_emitted_when_the_sweep_sealed_nothing() {
        // The floor has not elapsed, so nothing is sealed — there is no
        // StreamSealed to anchor, and an emission here would spend an
        // anchor write per tick for no statement.
        let a = Uuid::new_v4();
        let store = store_with_terminal_streams(&[a]);
        let hook = MockHook::ok(store.clone());
        let h = EventStoreArchiveHandler::new(
            sealing_uc(
                Arc::new(MockReader::with(vec![floor_not_elapsed(a)])),
                store.clone(),
            ),
            Some(hook.clone()),
        );

        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["deleted"], 0);
                assert_eq!(result_summary["skipped_floor_not_elapsed"], 1);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(
            hook.calls().is_empty(),
            "a sweep that sealed nothing must not emit a checkpoint"
        );
    }

    #[tokio::test]
    async fn no_hook_completes_the_sweep_and_anchors_nothing() {
        // `None` is the posture where `checkpoint_emission_status` is
        // Disabled (no S3 backend / no anchor keys). A missing
        // checkpoint is not a failure there (ADR 0057): the sweep seals
        // and reports Completed.
        let a = Uuid::new_v4();
        let store = store_with_terminal_streams(&[a]);
        let h = EventStoreArchiveHandler::new(
            sealing_uc(Arc::new(MockReader::with(vec![sealable(a)])), store.clone()),
            None,
        );

        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["deleted"], 1);
                assert_eq!(result_summary["errors"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(
            store.deleted_streams().len(),
            1,
            "the sweep's own sealing work is unaffected by the absent hook"
        );
    }

    #[tokio::test]
    async fn failed_emission_is_a_non_retrying_failure_that_names_the_sealed_streams() {
        // The rows are already gone, so the emission failure cannot
        // abort anything — but it must not read as a clean sweep
        // either. `retry: false`: a re-run finds those streams gone from
        // the candidate set, seals nothing, skips the emission and
        // reports Completed, which would erase the operator's only
        // signal.
        let a = Uuid::new_v4();
        let store = store_with_terminal_streams(&[a]);
        let hook = MockHook::failing(store.clone());
        let h = EventStoreArchiveHandler::new(
            sealing_uc(Arc::new(MockReader::with(vec![sealable(a)])), store.clone()),
            Some(hook.clone()),
        );

        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Failed { retry, reason } => {
                assert!(
                    !retry,
                    "re-running the sweep cannot anchor what the failed run sealed"
                );
                assert!(
                    reason.contains(&StreamId::artifact(a).to_string()),
                    "the reason must name the sealed-but-unanchored stream, got: {reason}"
                );
                assert!(
                    reason.contains("deleted=1"),
                    "the sweep's own sealing work must still be reported, got: {reason}"
                );
                assert!(
                    reason.contains("anchor object store unreachable"),
                    "the emission error must survive into the reason, got: {reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(
            hook.calls(),
            vec![1],
            "the emission was attempted once, after the seal committed"
        );
    }
}
