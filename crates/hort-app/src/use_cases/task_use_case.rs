//! Admin-task enqueue use case.
//!
//! # Responsibilities
//!
//! 1. **Kind validation** — rejects any `kind` not in the v1
//!    allowlist literals (CPU-only, fail-fast). Returns
//!    `AppError::Domain(DomainError::Validation(…))`.
//!
//! 2. **RBAC gate** — checks `Permission::AdminTaskInvoke` against the
//!    caller's resolved grants via [`RbacEvaluator::authorize`].
//!    Denial is logged at `info!` (audit signal, not error) and returns
//!    `AppError::Domain(DomainError::Forbidden(…))`.
//!
//! 3. **`jobs` INSERT** — delegates to [`JobsRepository::enqueue_task`].
//!    Returns the new row's id as `Uuid`.
//!
//! 4. **`TaskInvoked` append** — appends to the kind-routed audit stream
//!    ([`TaskUseCase::task_audit_stream`]): destructive kinds → the
//!    never-deleted
//!    [`StreamId::eventstore_retention`] audit-meta stream (the derived
//!    `admin-<v5-uuid>` id); every other kind → the single
//!    global authz stream ([`StreamId::authorization`]).
//!
//! 5. **Compensating delete** — if the event-store append fails, attempts a
//!    best-effort `JobsRepository::delete_job` to undo the INSERT. This is
//!    NOT a true two-phase commit: if the compensating delete also fails, the
//!    system is in a temporarily inconsistent state. The `jobs` row exists
//!    but no audit event was appended; the row will idle as `pending` and an
//!    operator can purge it manually. A doc comment on this limitation is
//!    placed on the compensating path below.
//!
//! # Observability
//!
//! - RBAC denial → `info!` log with `actor_user_id`, `kind`.
//! - `enqueue` instrumented with `#[tracing::instrument(skip(self))]`
//!   (architect-skill anti-pattern: do NOT use `#[instrument(err)]`).
//!
//! # Transaction semantics
//!
//! The `EventStore` port does not expose a way to share a `sqlx` transaction
//! with the `JobsRepository` port. The honest v1 contract is therefore:
//! insert the row → append the event. Failure of the append triggers a
//! compensating delete (best-effort). A future change that adds shared-
//! transaction support to the event-store port can replace this with a true
//! atomic two-phase write.

use std::sync::Arc;

use arc_swap::ArcSwap;
use uuid::Uuid;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::Permission;
use hort_domain::error::DomainError;
use hort_domain::events::{
    task_kind_is_destructive, Actor, ApiActor, DomainEvent, StreamId, TaskInvoked,
    DESTRUCTIVE_TASK_CLAIM, VALID_TASK_KINDS,
};
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::ports::jobs_repository::{
    EnqueueOutcome, JobRow, JobsRepository, ListJobsFilter, ListJobsPage,
};
use hort_domain::types::IdempotencyKey;

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::rbac::RbacEvaluator;

/// Application use case for admin-task enqueue operations.
pub struct TaskUseCase {
    jobs: Arc<dyn JobsRepository>,
    events: Arc<EventStorePublisher>,
    rbac: Arc<ArcSwap<RbacEvaluator>>,
}

impl TaskUseCase {
    /// Construct a new `TaskUseCase`.
    pub fn new(
        jobs: Arc<dyn JobsRepository>,
        events: Arc<EventStorePublisher>,
        rbac: Arc<ArcSwap<RbacEvaluator>>,
    ) -> Self {
        Self { jobs, events, rbac }
    }

    /// Authorize `actor` to invoke task `kind`, **before** any param
    /// parsing, idempotency probe, or port I/O.
    ///
    /// Two-factor, fail-safe-by-AND:
    ///
    /// 1. The existing coarse gate — `Permission::AdminTaskInvoke` via
    ///    [`RbacEvaluator::authorize`] (unchanged for every kind).
    /// 2. **For destructive kinds only** ([`task_kind_is_destructive`] —
    ///    `retention-purge` / `eventstore-archive` / `retention-evaluate`):
    ///    the caller's resolved `principal.claims` must additionally
    ///    satisfy the [`DESTRUCTIVE_TASK_CLAIM`] requirement, evaluated
    ///    through the **same** `RbacEvaluator` claim subset-match the
    ///    grant model uses for `GrantSubject::Claims` — *not* a hand-rolled
    ///    parallel evaluator. The synthetic `"admin"` claim short-circuits
    ///    it exactly as it short-circuits every other authz decision
    ///    (a full admin already holds every authority).
    ///
    /// Ordinary kinds keep **exactly** today's `AdminTaskInvoke`-only
    /// gate — zero behaviour change for `noop`/`scan`/etc.
    ///
    /// Denial is logged at `info!` (audit signal, NOT `err`) naming the
    /// missing authority and returns
    /// `AppError::Domain(DomainError::Forbidden(…))`. Called both at the
    /// handler boundary (so an unauthorized caller is rejected before
    /// param-validate / idempotency lookup) **and** internally by
    /// [`Self::enqueue`] (defense-in-depth — a direct use-case caller is
    /// still gated).
    #[tracing::instrument(skip(self))]
    pub fn authorize_kind(&self, actor: &CallerPrincipal, kind: &str) -> AppResult<()> {
        let rbac = self.rbac.load();

        // Factor 1 — the unchanged coarse `AdminTaskInvoke` gate.
        if !rbac.authorize(actor, Permission::AdminTaskInvoke, None) {
            tracing::info!(
                actor_user_id = %actor.user_id,
                kind,
                "TaskUseCase authz denied — Permission::AdminTaskInvoke not held",
            );
            return Err(AppError::Domain(DomainError::Forbidden(format!(
                "Permission::AdminTaskInvoke required to invoke task kind {kind:?}"
            ))));
        }

        // Factor 2 — destructive kinds need the extra claim. Reuse the
        // RbacEvaluator claim subset-match (incl. the synthetic-`admin`
        // short-circuit) by checking a synthetic single-claim requirement
        // against the same evaluator semantics, rather than re-deriving
        // the subset test here.
        if task_kind_is_destructive(kind)
            && !rbac.claims_satisfy(actor, std::slice::from_ref(&DESTRUCTIVE_TASK_CLAIM))
        {
            tracing::info!(
                actor_user_id = %actor.user_id,
                kind,
                required_claim = DESTRUCTIVE_TASK_CLAIM,
                "TaskUseCase authz denied — destructive task kind requires the \
                 task:destructive claim in addition to Permission::AdminTaskInvoke",
            );
            return Err(AppError::Domain(DomainError::Forbidden(format!(
                "destructive task kind {kind:?} requires the {DESTRUCTIVE_TASK_CLAIM:?} \
                 claim in addition to Permission::AdminTaskInvoke"
            ))));
        }

        if task_kind_is_destructive(kind) {
            tracing::info!(
                actor_user_id = %actor.user_id,
                kind,
                "destructive admin task authorized (Permission::AdminTaskInvoke + \
                 task:destructive claim)",
            );
        }

        Ok(())
    }

    /// Route the audit `TaskInvoked` for task `kind` to the correct
    /// event stream.
    ///
    /// Destructive kinds (`retention-purge`, `eventstore-archive`,
    /// `retention-evaluate` — the **closed** domain set classified by
    /// [`task_kind_is_destructive`] / `DESTRUCTIVE_TASK_KINDS`) route to
    /// [`StreamId::eventstore_retention`], the never-deleted audit-meta
    /// stream (the derived `admin-<v5-uuid>` id) that
    /// `EventStore::delete_stream` / `archive_stream` are forbidden to
    /// touch. The point: an `eventstore-archive` or
    /// `retention-purge` of the Authorization category cannot truncate
    /// its own invocation trail, because the trail does not live on the
    /// Authorization stream.
    ///
    /// Every other kind (`noop`, `scan`, …) — and, fail-safe, any
    /// unrecognised string the upstream `VALID_TASK_KINDS` allowlist
    /// would have rejected — routes to [`StreamId::authorization`],
    /// exactly as before: zero behaviour change for non-destructive
    /// kinds.
    ///
    /// Pure, zero-I/O, total. Reuses the existing closed domain
    /// classifier — it does **not** introduce a parallel destructive-kind
    /// list (a new classifier here would be the scope-creep regression
    /// `DESTRUCTIVE_TASK_KINDS`'s doc warns against).
    ///
    /// **Split emit-sites (intentional):**
    /// `TaskUseCase` only ever emits `TaskInvoked`; the `TaskFailed`
    /// audit record is emitted by the worker dispatcher (in
    /// worker code), not here.
    /// This shared pure helper is the single reuse point a future
    /// `TaskFailed` emit-site is expected to call so both records land on
    /// the same exempt stream.
    #[must_use]
    pub fn task_audit_stream(kind: &str) -> StreamId {
        if task_kind_is_destructive(kind) {
            StreamId::eventstore_retention()
        } else {
            StreamId::authorization()
        }
    }

    /// Enqueue an admin task.
    ///
    /// Steps:
    /// 1. Validate `kind` is in the v1 allowlist.
    /// 2. Per-kind authz via [`Self::authorize_kind`] (coarse
    ///    `AdminTaskInvoke` AND, for destructive kinds, the
    ///    `task:destructive` claim).
    /// 3. Insert a `jobs` row with `status='pending'` via `JobsRepository::enqueue_task`.
    /// 4. Append `TaskInvoked` on the kind-routed audit stream
    ///    ([`Self::task_audit_stream`] — destructive kinds land on the
    ///    never-deleted `eventstore_retention()` stream; all others on
    ///    `authorization()`).
    /// 5. If the append fails, attempt a compensating delete (best-effort).
    ///
    /// Returns the [`EnqueueOutcome`] on success — [`EnqueueOutcome::Enqueued`]
    /// for a fresh insert (the common case) or [`EnqueueOutcome::Duplicate`]
    /// when an `idempotency_key` collides with an existing row's
    /// per-UTC-day claim (ADR 0028).
    ///
    /// # `idempotency_key` semantics
    ///
    /// - `None` preserves today's behaviour exactly: the DB-side
    ///   partial-unique check is inert, every call produces a fresh
    ///   `EnqueueOutcome::Enqueued`. Non-destructive call sites pass
    ///   `None`.
    /// - `Some(k)` engages the `jobs_idempotency_key_uq` partial-unique
    ///   index. A second call with the same key returns
    ///   `EnqueueOutcome::Duplicate { existing_job_id }` — the existing
    ///   row's id, no new insert (the original
    ///   enqueue already owns the jobs row). The key is derived
    ///   server-side for destructive kinds.
    ///
    /// # Audit semantics
    ///
    /// Both branches emit `TaskInvoked`. On the `Duplicate` branch the
    /// event carries `duplicate_of: Some(existing_job_id)`, so a dedup
    /// hit is auditable distinct from a fresh enqueue rather than
    /// double-counting as one.
    ///
    /// # RBAC denial
    ///
    /// Denial is logged at `info!` (audit signal). The returned error is
    /// `AppError::Domain(DomainError::Forbidden(…))`.
    ///
    /// # Compensating-delete limitation
    ///
    /// The INSERT and the event-store append are not inside a shared
    /// Postgres transaction (the `EventStore` port does not expose one).
    /// If the append fails, we attempt `delete_job` to undo the INSERT.
    /// If that also fails, the `jobs` row exists without an audit event.
    /// An operator can identify and remove orphaned rows by looking for
    /// `status='pending'` rows with no corresponding `TaskInvoked` event
    /// on the kind-routed audit stream (the `authorization()` stream for
    /// ordinary kinds, the `eventstore_retention()` audit-meta stream for
    /// destructive kinds) for the same `job_id`.
    #[tracing::instrument(skip(self))]
    pub async fn enqueue(
        &self,
        actor: &CallerPrincipal,
        kind: &str,
        params: &serde_json::Value,
        idempotency_key: Option<&IdempotencyKey>,
    ) -> AppResult<EnqueueOutcome> {
        // 1. Validate kind before doing any I/O.
        if !VALID_TASK_KINDS.contains(&kind) {
            return Err(AppError::Domain(DomainError::Validation(format!(
                "unknown task kind {kind:?}; expected one of {VALID_TASK_KINDS:?}"
            ))));
        }

        // 2. Per-kind authz (defense-in-depth: the handler calls this
        //    first, before param-validate / idempotency probe; calling it
        //    again here keeps a direct use-case caller independently
        //    gated). Shared logic — no parallel evaluator.
        self.authorize_kind(actor, kind)?;

        // 3. Insert jobs row. `trigger_source = "manual"` mirrors
        //    `TriggerSource::Manual` — the admin-task POST is operator-
        //    initiated even when the operator is a chart CronJob, and
        //    `"manual"` is the only literal in
        //    `migration_009`'s CHECK constraint that fits "an outside
        //    caller asked us to enqueue this". Earlier drafts passed
        //    `"api"`, which was not in the allow-list and surfaced as
        //    a 23514 constraint violation → 500 to the caller.
        let outcome = self
            .jobs
            .enqueue_task(
                kind,
                params,
                Some(actor.user_id),
                0,
                "manual",
                idempotency_key,
            )
            .await?;

        // 4. Resolve the audit shape from the outcome.
        //
        //    Both
        //    branches emit `TaskInvoked`, with `duplicate_of` flagging
        //    the dedup hit. On the `Duplicate` branch, `task_job_id`
        //    carries the *existing* row's id — the row that was
        //    logically enqueued — and `duplicate_of = Some(existing_id)`
        //    marks this as a DB partial-unique-index dedup event so
        //    reviewers can reconstruct dedup decisions from the audit
        //    stream without correlating against the `jobs` table.
        let (audit_job_id, duplicate_of, is_fresh_enqueue) = match outcome {
            EnqueueOutcome::Enqueued { job_id } => (job_id, None, true),
            EnqueueOutcome::Duplicate { existing_job_id } => {
                (existing_job_id, Some(existing_job_id), false)
            }
        };

        // 5. Compute params digest and append TaskInvoked. The audit
        //    stream is kind-dependent:
        //    destructive kinds route to the never-deleted
        //    `eventstore_retention()` audit-meta stream so a destructive
        //    run cannot truncate its own invocation trail; every other
        //    kind stays on `authorization()` (no behaviour change).
        let params_digest = TaskInvoked::compute_params_digest(params);
        let stream_id = Self::task_audit_stream(kind);
        let append = AppendEvents {
            stream_id: stream_id.clone(),
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(DomainEvent::TaskInvoked(TaskInvoked {
                task_job_id: audit_job_id,
                kind: kind.to_string(),
                params_digest,
                duplicate_of,
            }))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: actor.user_id,
            }),
        };

        if let Err(append_err) = self.events.append(append).await {
            // 6. Compensating delete — best-effort; log the outcome but do
            //    NOT mask the original error.
            //
            //    **Only the fresh-enqueue branch compensates.** On the
            //    `Duplicate` branch the existing row is owned by the
            //    prior enqueue's audit chain; deleting it would corrupt
            //    that chain (and undo a prior successful audit). We
            //    surface the append error to the caller verbatim; the
            //    next same-day enqueue will dedup against the existing
            //    row again, and the operator-visible failure is the
            //    missing TaskInvoked on the duplicate event itself.
            //
            // Limitation: if the compensating delete also fails on the
            // fresh-enqueue path, the `jobs` row exists without an audit
            // event. See module-level doc for recovery guidance.
            tracing::warn!(
                job_id = %audit_job_id,
                kind,
                duplicate = !is_fresh_enqueue,
                error = %append_err,
                "TaskInvoked append failed",
            );
            if is_fresh_enqueue {
                if let Err(del_err) = self.jobs.delete_job(audit_job_id).await {
                    tracing::error!(
                        job_id = %audit_job_id,
                        kind,
                        error = %del_err,
                        "compensating delete of jobs row failed — row may be orphaned; \
                         operator should inspect jobs WHERE id = job_id",
                    );
                }
            }
            return Err(append_err.into());
        }

        Ok(outcome)
    }

    /// List jobs with optional filtering and cursor-based pagination.
    ///
    /// Delegates to [`JobsRepository::list_jobs`]. Read-only — no RBAC
    /// check beyond requiring a valid principal at the handler layer.
    #[tracing::instrument(skip(self))]
    pub async fn list_jobs(
        &self,
        filter: ListJobsFilter,
        limit: u32,
        cursor: Option<Uuid>,
    ) -> AppResult<ListJobsPage> {
        self.jobs
            .list_jobs(filter, limit, cursor)
            .await
            .map_err(AppError::from)
    }

    /// Fetch a single jobs row by id.
    ///
    /// Returns `Ok(None)` when the row does not exist. Read-only.
    #[tracing::instrument(skip(self))]
    pub async fn get_job(&self, job_id: Uuid) -> AppResult<Option<JobRow>> {
        self.jobs.get_job(job_id).await.map_err(AppError::from)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use uuid::Uuid;

    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::events::{
        DomainEvent, PersistedEvent, StreamCategory, StreamId, TaskInvoked, VALID_TASK_KINDS,
    };
    use hort_domain::ports::event_store::{
        AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
    };
    use hort_domain::ports::jobs_repository::{JobsRepository, ScanJob};
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ContentHash;

    use crate::rbac::RbacEvaluator;

    // -----------------------------------------------------------------------
    // Mock infrastructure
    // -----------------------------------------------------------------------

    /// Mock that panics on any call — used for the "port must never be called"
    /// assertions (RBAC denial, kind validation failure).
    struct PanicJobsRepository;

    impl JobsRepository for PanicJobsRepository {
        fn claim_scan_jobs<'a>(
            &'a self,
            _worker_id: &'a str,
            _batch_size: u32,
            _lock_duration: Duration,
        ) -> BoxFuture<'a, DomainResult<Vec<ScanJob>>> {
            panic!("PanicJobsRepository::claim_scan_jobs must not be called");
        }
        fn mark_completed<'a>(
            &'a self,
            _job_id: Uuid,
            _result_summary: serde_json::Value,
        ) -> BoxFuture<'a, DomainResult<()>> {
            panic!("PanicJobsRepository::mark_completed must not be called");
        }
        fn reschedule<'a>(
            &'a self,
            _job_id: Uuid,
            _backoff: Duration,
            _last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<()>> {
            panic!("PanicJobsRepository::reschedule must not be called");
        }
        fn mark_failed<'a>(
            &'a self,
            _job_id: Uuid,
            _last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<()>> {
            panic!("PanicJobsRepository::mark_failed must not be called");
        }
        fn enqueue_scan<'a>(
            &'a self,
            _artifact_id: Uuid,
            _repository_id: Uuid,
            _content_hash: &'a ContentHash,
            _format: &'a str,
            _priority: i16,
            _trigger_source: &'a str,
        ) -> BoxFuture<'a, DomainResult<Uuid>> {
            panic!("PanicJobsRepository::enqueue_scan must not be called");
        }
        fn enqueue_task<'a>(
            &'a self,
            _kind: &'a str,
            _params: &'a serde_json::Value,
            _actor_id: Option<Uuid>,
            _priority: i16,
            _trigger_source: &'a str,
            _idempotency_key: Option<&'a IdempotencyKey>,
        ) -> BoxFuture<'a, DomainResult<EnqueueOutcome>> {
            panic!("PanicJobsRepository::enqueue_task must not be called");
        }
        fn delete_job<'a>(&'a self, _job_id: Uuid) -> BoxFuture<'a, DomainResult<()>> {
            panic!("PanicJobsRepository::delete_job must not be called");
        }
    }

    /// Mock that panics on any call — used for the "event store must never be
    /// called" assertions (RBAC denial, kind validation failure).
    struct PanicEventStore;

    impl EventStore for PanicEventStore {
        fn append(&self, _batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
            panic!("PanicEventStore::append must not be called");
        }
        fn read_stream(
            &self,
            _stream_id: &StreamId,
            _from: ReadFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            panic!("PanicEventStore::read_stream must not be called");
        }
        fn read_category(
            &self,
            _category: StreamCategory,
            _from: SubscribeFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            panic!("PanicEventStore::read_category must not be called");
        }
        fn delete_stream(&self, _stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>> {
            panic!("PanicEventStore::delete_stream must not be called");
        }
        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
        ) -> BoxFuture<'_, DomainResult<()>> {
            panic!("PanicEventStore::archive_stream must not be called");
        }
    }

    /// Recorded call to `enqueue_task`.
    #[derive(Debug, Clone)]
    struct EnqueueCall {
        kind: String,
        params: serde_json::Value,
        actor_id: Option<Uuid>,
        /// The idempotency key passed by the
        /// caller (cloned, since the mock cannot retain the borrow).
        /// `None` is the non-destructive default; `Some(_)` is the
        /// destructive-cron path.
        idempotency_key: Option<IdempotencyKey>,
    }

    /// Recorded call to `delete_job`.
    #[derive(Debug, Clone)]
    struct DeleteCall {
        job_id: Uuid,
    }

    /// Mock `JobsRepository` that records calls and returns a fixed `Uuid`.
    struct RecordingJobsRepository {
        enqueue_calls: Mutex<Vec<EnqueueCall>>,
        delete_calls: Mutex<Vec<DeleteCall>>,
        return_id: Uuid,
        enqueue_error: Option<DomainError>,
        /// When `Some`, `enqueue_task` returns
        /// `EnqueueOutcome::Duplicate { existing_job_id }` instead of
        /// `Enqueued`. Used by the unit tests pinning the
        /// pass-through semantics on the Duplicate branch.
        duplicate_existing_id: Option<Uuid>,
    }

    impl RecordingJobsRepository {
        fn new(return_id: Uuid) -> Self {
            Self {
                enqueue_calls: Mutex::new(Vec::new()),
                delete_calls: Mutex::new(Vec::new()),
                return_id,
                enqueue_error: None,
                duplicate_existing_id: None,
            }
        }

        /// Make `enqueue_task` return
        /// `EnqueueOutcome::Duplicate { existing_job_id }` instead of
        /// the default `Enqueued` outcome.
        fn with_duplicate(existing: Uuid) -> Self {
            Self {
                enqueue_calls: Mutex::new(Vec::new()),
                delete_calls: Mutex::new(Vec::new()),
                return_id: Uuid::nil(),
                enqueue_error: None,
                duplicate_existing_id: Some(existing),
            }
        }

        fn enqueue_calls(&self) -> Vec<EnqueueCall> {
            self.enqueue_calls.lock().unwrap().clone()
        }

        fn delete_calls(&self) -> Vec<DeleteCall> {
            self.delete_calls.lock().unwrap().clone()
        }
    }

    impl JobsRepository for RecordingJobsRepository {
        fn claim_scan_jobs<'a>(
            &'a self,
            _worker_id: &'a str,
            _batch_size: u32,
            _lock_duration: Duration,
        ) -> BoxFuture<'a, DomainResult<Vec<ScanJob>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn mark_completed<'a>(
            &'a self,
            _job_id: Uuid,
            _result_summary: serde_json::Value,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn reschedule<'a>(
            &'a self,
            _job_id: Uuid,
            _backoff: Duration,
            _last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn mark_failed<'a>(
            &'a self,
            _job_id: Uuid,
            _last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn enqueue_scan<'a>(
            &'a self,
            _artifact_id: Uuid,
            _repository_id: Uuid,
            _content_hash: &'a ContentHash,
            _format: &'a str,
            _priority: i16,
            _trigger_source: &'a str,
        ) -> BoxFuture<'a, DomainResult<Uuid>> {
            Box::pin(async { Ok(Uuid::nil()) })
        }
        fn enqueue_task<'a>(
            &'a self,
            kind: &'a str,
            params: &'a serde_json::Value,
            actor_id: Option<Uuid>,
            _priority: i16,
            _trigger_source: &'a str,
            idempotency_key: Option<&'a IdempotencyKey>,
        ) -> BoxFuture<'a, DomainResult<EnqueueOutcome>> {
            self.enqueue_calls.lock().unwrap().push(EnqueueCall {
                kind: kind.to_string(),
                params: params.clone(),
                actor_id,
                idempotency_key: idempotency_key.cloned(),
            });
            if let Some(ref e) = self.enqueue_error {
                let e = e.clone();
                Box::pin(async move { Err(e) })
            } else if let Some(existing) = self.duplicate_existing_id {
                Box::pin(async move {
                    Ok(EnqueueOutcome::Duplicate {
                        existing_job_id: existing,
                    })
                })
            } else {
                let id = self.return_id;
                Box::pin(async move { Ok(EnqueueOutcome::Enqueued { job_id: id }) })
            }
        }
        fn delete_job<'a>(&'a self, job_id: Uuid) -> BoxFuture<'a, DomainResult<()>> {
            self.delete_calls
                .lock()
                .unwrap()
                .push(DeleteCall { job_id });
            Box::pin(async { Ok(()) })
        }
    }

    /// Recorded call to `EventStore::append`.
    #[derive(Debug, Clone)]
    struct AppendCall {
        batch: AppendEvents,
    }

    /// Mock `EventStore` that records appends and can be configured to fail.
    struct RecordingEventStore {
        append_calls: Mutex<Vec<AppendCall>>,
        fail_on_append: bool,
    }

    impl RecordingEventStore {
        fn new() -> Self {
            Self {
                append_calls: Mutex::new(Vec::new()),
                fail_on_append: false,
            }
        }

        fn new_failing() -> Self {
            Self {
                append_calls: Mutex::new(Vec::new()),
                fail_on_append: true,
            }
        }

        fn append_calls(&self) -> Vec<AppendCall> {
            self.append_calls.lock().unwrap().clone()
        }
    }

    impl EventStore for RecordingEventStore {
        fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
            self.append_calls.lock().unwrap().push(AppendCall {
                batch: batch.clone(),
            });
            if self.fail_on_append {
                Box::pin(async { Err(DomainError::Conflict("mock event-store conflict".into())) })
            } else {
                Box::pin(async {
                    Ok(AppendResult {
                        stream_position: 0,
                        global_positions: vec![0],
                    })
                })
            }
        }
        fn read_stream(
            &self,
            _stream_id: &StreamId,
            _from: ReadFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn read_category(
            &self,
            _category: StreamCategory,
            _from: SubscribeFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn delete_stream(&self, _stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // -----------------------------------------------------------------------
    // RBAC helpers
    // -----------------------------------------------------------------------

    /// Build an `RbacEvaluator` that grants `Permission::AdminTaskInvoke`
    /// to any caller carrying the `"task-admin"` claim (claim-based
    /// subject model — `Claims(["task-admin"])`).
    fn rbac_with_task_invoke() -> Arc<ArcSwap<RbacEvaluator>> {
        let grant = PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["task-admin".to_string()]),
            repository_id: None,
            permission: Permission::AdminTaskInvoke,
            created_at: chrono::Utc::now(),
            managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
            managed_by_digest: None,
        };
        let evaluator = RbacEvaluator::new(vec![grant]);
        Arc::new(ArcSwap::from_pointee(evaluator))
    }

    /// Build an `RbacEvaluator` that has NO grants at all (denies everything).
    fn rbac_deny_all() -> Arc<ArcSwap<RbacEvaluator>> {
        let evaluator = RbacEvaluator::new(vec![]);
        Arc::new(ArcSwap::from_pointee(evaluator))
    }

    /// Build a `CallerPrincipal` that carries the `"task-admin"` claim.
    fn caller_with_task_admin_role() -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test-user".into(),
            username: "test-user".into(),
            email: "test@example.com".into(),
            claims: vec!["task-admin".into()],
            token_kind: None,
            issued_at: chrono::Utc::now(),
            token_cap: None,
        }
    }

    /// Build a `CallerPrincipal` that carries `task-admin` AND the
    /// `task:destructive` claim — authorised for destructive kinds.
    fn caller_with_destructive_claim() -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "destructive-user".into(),
            username: "destructive-user".into(),
            email: "destructive@example.com".into(),
            claims: vec!["task-admin".into(), "task:destructive".into()],
            token_kind: None,
            issued_at: chrono::Utc::now(),
            token_cap: None,
        }
    }

    /// Build a `CallerPrincipal` that carries no claims.
    fn caller_no_roles() -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "no-roles-user".into(),
            username: "no-roles-user".into(),
            email: "noroles@example.com".into(),
            claims: vec![],
            token_kind: None,
            issued_at: chrono::Utc::now(),
            token_cap: None,
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// Test 6 — happy path: RBAC says yes, jobs returns Uuid, event store accepts.
    #[tokio::test]
    async fn enqueue_happy_path() {
        let expected_job_id = Uuid::new_v4();
        let jobs = Arc::new(RecordingJobsRepository::new(expected_job_id));
        let events = Arc::new(RecordingEventStore::new());
        let rbac = rbac_with_task_invoke();
        let use_case = TaskUseCase::new(
            Arc::clone(&jobs) as _,
            crate::event_store_publisher::wrap_for_test(Arc::clone(&events)),
            rbac,
        );

        let actor = caller_with_task_admin_role();
        let params = serde_json::json!({"dry_run": false});
        let result = use_case.enqueue(&actor, "noop", &params, None).await;

        // Returned outcome matches what jobs returned.
        let outcome = result.expect("expected Ok");
        assert_eq!(
            outcome,
            EnqueueOutcome::Enqueued {
                job_id: expected_job_id
            }
        );

        // jobs port received correct (kind, params, actor_id, idempotency_key) tuple.
        let calls = jobs.enqueue_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].kind, "noop");
        assert_eq!(calls[0].params, params);
        assert_eq!(calls[0].actor_id, Some(actor.user_id));
        assert!(
            calls[0].idempotency_key.is_none(),
            "non-destructive caller passes None"
        );

        // Event store received exactly one TaskInvoked on Authorization stream.
        let append_calls = events.append_calls();
        assert_eq!(append_calls.len(), 1);
        let batch = &append_calls[0].batch;
        assert_eq!(batch.stream_id.category, StreamCategory::Authorization);
        assert_eq!(batch.events.len(), 1);
        match &batch.events[0].event {
            DomainEvent::TaskInvoked(payload) => {
                assert_eq!(payload.task_job_id, expected_job_id);
                assert_eq!(payload.kind, "noop");
                // params_digest validates as a 64-char lowercase hex string.
                assert_eq!(payload.params_digest.len(), 64);
                assert!(payload
                    .params_digest
                    .chars()
                    .all(|c| matches!(c, '0'..='9' | 'a'..='f')));
            }
            other => panic!("expected TaskInvoked, got {other:?}"),
        }
    }

    /// Test 7 — RBAC denial: jobs and event store are never called.
    #[tokio::test]
    async fn enqueue_rbac_denied_does_not_call_ports() {
        let jobs: Arc<dyn JobsRepository> = Arc::new(PanicJobsRepository);
        let events: Arc<EventStorePublisher> =
            crate::event_store_publisher::wrap_for_test(Arc::new(PanicEventStore));
        let rbac = rbac_deny_all();
        let use_case = TaskUseCase::new(jobs, events, rbac);

        let actor = caller_no_roles();
        let params = serde_json::json!({});
        let result = use_case.enqueue(&actor, "noop", &params, None).await;

        assert!(
            matches!(result, Err(AppError::Domain(DomainError::Forbidden(_)))),
            "expected Forbidden, got {result:?}"
        );
    }

    /// Test 8 — unknown kind: no port calls.
    #[tokio::test]
    async fn enqueue_unknown_kind_returns_validation_error() {
        let jobs: Arc<dyn JobsRepository> = Arc::new(PanicJobsRepository);
        let events: Arc<EventStorePublisher> =
            crate::event_store_publisher::wrap_for_test(Arc::new(PanicEventStore));
        // Even with a fully-authorised RBAC, kind validation fires first.
        let rbac = rbac_with_task_invoke();
        let use_case = TaskUseCase::new(jobs, events, rbac);

        let actor = caller_with_task_admin_role();
        let params = serde_json::json!({});
        let result = use_case.enqueue(&actor, "bogus-kind", &params, None).await;

        assert!(
            matches!(result, Err(AppError::Domain(DomainError::Validation(_)))),
            "expected Validation, got {result:?}"
        );
    }

    /// Test 9 — event-store append failure triggers compensating delete.
    #[tokio::test]
    async fn enqueue_event_store_failure_triggers_compensating_delete() {
        let expected_job_id = Uuid::new_v4();
        let jobs = Arc::new(RecordingJobsRepository::new(expected_job_id));
        let events = Arc::new(RecordingEventStore::new_failing());
        let rbac = rbac_with_task_invoke();
        let use_case = TaskUseCase::new(
            Arc::clone(&jobs) as _,
            crate::event_store_publisher::wrap_for_test(Arc::clone(&events)),
            rbac,
        );

        let actor = caller_with_task_admin_role();
        let params = serde_json::json!({"kind": "test"});
        let result = use_case.enqueue(&actor, "noop", &params, None).await;

        // Overall enqueue fails.
        assert!(result.is_err(), "expected Err after event-store failure");

        // Compensating delete was called with the correct job_id.
        let delete_calls = jobs.delete_calls();
        assert_eq!(delete_calls.len(), 1);
        assert_eq!(delete_calls[0].job_id, expected_job_id);
    }

    /// Test 10 — params_digest in the emitted TaskInvoked matches blake3 of params.
    #[tokio::test]
    async fn enqueue_params_digest_matches_blake3_of_params() {
        let expected_job_id = Uuid::new_v4();
        let jobs = Arc::new(RecordingJobsRepository::new(expected_job_id));
        let events = Arc::new(RecordingEventStore::new());
        let rbac = rbac_with_task_invoke();
        let use_case = TaskUseCase::new(
            Arc::clone(&jobs) as _,
            crate::event_store_publisher::wrap_for_test(Arc::clone(&events)),
            rbac,
        );

        let actor = caller_with_task_admin_role();
        let params = serde_json::json!({"target": "npm-registry", "limit": 42});
        use_case
            .enqueue(&actor, "scan", &params, None)
            .await
            .unwrap();

        let append_calls = events.append_calls();
        assert_eq!(append_calls.len(), 1);
        let DomainEvent::TaskInvoked(payload) = &append_calls[0].batch.events[0].event else {
            panic!("expected TaskInvoked");
        };

        // Re-compute the expected digest and compare.
        let expected_digest = TaskInvoked::compute_params_digest(&params);
        assert_eq!(payload.params_digest, expected_digest);
    }

    /// Test — every value in `VALID_TASK_KINDS` is accepted.
    #[tokio::test]
    async fn enqueue_all_valid_kinds_accepted() {
        for kind in VALID_TASK_KINDS {
            let job_id = Uuid::new_v4();
            let jobs = Arc::new(RecordingJobsRepository::new(job_id));
            let events = Arc::new(RecordingEventStore::new());
            let rbac = rbac_with_task_invoke();
            let use_case = TaskUseCase::new(
                Arc::clone(&jobs) as _,
                crate::event_store_publisher::wrap_for_test(Arc::clone(&events)),
                rbac,
            );

            // Caller carries BOTH factors (AdminTaskInvoke + the
            // task:destructive claim) so this "every valid kind is
            // accepted" assertion holds across ordinary AND destructive
            // kinds under the per-kind destructive tier.
            let actor = caller_with_destructive_claim();
            let params = serde_json::json!({});
            let result = use_case.enqueue(&actor, kind, &params, None).await;
            assert!(
                result.is_ok(),
                "expected Ok for valid kind {kind:?}, got {result:?}"
            );
        }
    }

    /// Test 11 — unknown kind fails before RBAC, even for unauthorized
    /// caller. This pins the order-of-checks invariant: kind validation
    /// (CPU-only, fail-fast) must fire before RBAC (requires port calls).
    #[tokio::test]
    async fn enqueue_unknown_kind_before_rbac_even_for_unauthorized_caller() {
        let jobs: Arc<dyn JobsRepository> = Arc::new(PanicJobsRepository);
        let events: Arc<EventStorePublisher> =
            crate::event_store_publisher::wrap_for_test(Arc::new(PanicEventStore));
        let rbac = rbac_deny_all();
        let use_case = TaskUseCase::new(jobs, events, rbac);
        let actor = caller_no_roles();
        let result = use_case
            .enqueue(&actor, "bogus-kind", &serde_json::json!({}), None)
            .await;
        assert!(
            matches!(result, Err(AppError::Domain(DomainError::Validation(_)))),
            "kind validation must fire before RBAC; got {result:?}"
        );
    }

    // -- Per-kind destructive tier ------------------------------------------

    /// `authorize_kind`: ordinary kind requires only `AdminTaskInvoke`
    /// (zero behaviour change for `noop`).
    #[tokio::test]
    async fn authorize_kind_ordinary_allows_with_admin_task_invoke_only() {
        let jobs: Arc<dyn JobsRepository> = Arc::new(PanicJobsRepository);
        let events: Arc<EventStorePublisher> =
            crate::event_store_publisher::wrap_for_test(Arc::new(PanicEventStore));
        let use_case = TaskUseCase::new(jobs, events, rbac_with_task_invoke());
        let actor = caller_with_task_admin_role();
        assert!(use_case.authorize_kind(&actor, "noop").is_ok());
    }

    /// `authorize_kind`: a caller WITHOUT `AdminTaskInvoke` is denied an
    /// ordinary kind (unchanged coarse gate).
    #[tokio::test]
    async fn authorize_kind_ordinary_denied_without_admin_task_invoke() {
        let jobs: Arc<dyn JobsRepository> = Arc::new(PanicJobsRepository);
        let events: Arc<EventStorePublisher> =
            crate::event_store_publisher::wrap_for_test(Arc::new(PanicEventStore));
        let use_case = TaskUseCase::new(jobs, events, rbac_deny_all());
        let actor = caller_no_roles();
        assert!(matches!(
            use_case.authorize_kind(&actor, "noop"),
            Err(AppError::Domain(DomainError::Forbidden(_)))
        ));
    }

    /// `authorize_kind`: a destructive kind is DENIED when the caller
    /// holds `AdminTaskInvoke` but NOT the `task:destructive` claim.
    #[tokio::test]
    async fn authorize_kind_destructive_denied_without_destructive_claim() {
        let jobs: Arc<dyn JobsRepository> = Arc::new(PanicJobsRepository);
        let events: Arc<EventStorePublisher> =
            crate::event_store_publisher::wrap_for_test(Arc::new(PanicEventStore));
        let use_case = TaskUseCase::new(jobs, events, rbac_with_task_invoke());
        let actor = caller_with_task_admin_role(); // has AdminTaskInvoke, no task:destructive
        for kind in [
            "retention-purge",
            "eventstore-archive",
            "retention-evaluate",
        ] {
            let r = use_case.authorize_kind(&actor, kind);
            assert!(
                matches!(r, Err(AppError::Domain(DomainError::Forbidden(_)))),
                "destructive kind {kind:?} must be Forbidden without the claim; got {r:?}"
            );
        }
    }

    /// `authorize_kind`: a destructive kind is ALLOWED when the caller
    /// holds `AdminTaskInvoke` AND the `task:destructive` claim.
    #[tokio::test]
    async fn authorize_kind_destructive_allowed_with_destructive_claim() {
        let jobs: Arc<dyn JobsRepository> = Arc::new(PanicJobsRepository);
        let events: Arc<EventStorePublisher> =
            crate::event_store_publisher::wrap_for_test(Arc::new(PanicEventStore));
        let use_case = TaskUseCase::new(jobs, events, rbac_with_task_invoke());
        let actor = caller_with_destructive_claim();
        for kind in [
            "retention-purge",
            "eventstore-archive",
            "retention-evaluate",
        ] {
            assert!(
                use_case.authorize_kind(&actor, kind).is_ok(),
                "destructive kind {kind:?} must be allowed with the claim"
            );
        }
    }

    /// `authorize_kind`: a destructive kind is still DENIED for a caller
    /// who has the `task:destructive` claim but NOT `AdminTaskInvoke`
    /// (the two-factor AND — claim alone is insufficient).
    #[tokio::test]
    async fn authorize_kind_destructive_denied_with_claim_but_no_admin_task_invoke() {
        let jobs: Arc<dyn JobsRepository> = Arc::new(PanicJobsRepository);
        let events: Arc<EventStorePublisher> =
            crate::event_store_publisher::wrap_for_test(Arc::new(PanicEventStore));
        // rbac_deny_all → AdminTaskInvoke never granted.
        let use_case = TaskUseCase::new(jobs, events, rbac_deny_all());
        let mut actor = caller_no_roles();
        actor.claims = vec!["task:destructive".into()];
        assert!(matches!(
            use_case.authorize_kind(&actor, "retention-purge"),
            Err(AppError::Domain(DomainError::Forbidden(_)))
        ));
    }

    /// Defense-in-depth: a direct `enqueue` call (bypassing the handler)
    /// is still gated by the same per-kind authz — destructive kind
    /// without the claim is denied even though ports would otherwise run.
    #[tokio::test]
    async fn enqueue_destructive_denied_without_claim_does_not_call_ports() {
        let jobs: Arc<dyn JobsRepository> = Arc::new(PanicJobsRepository);
        let events: Arc<EventStorePublisher> =
            crate::event_store_publisher::wrap_for_test(Arc::new(PanicEventStore));
        let use_case = TaskUseCase::new(jobs, events, rbac_with_task_invoke());
        let actor = caller_with_task_admin_role(); // AdminTaskInvoke only
        let result = use_case
            .enqueue(&actor, "retention-purge", &serde_json::json!({}), None)
            .await;
        assert!(
            matches!(result, Err(AppError::Domain(DomainError::Forbidden(_)))),
            "direct enqueue of destructive kind must stay gated; got {result:?}"
        );
    }

    /// Defense-in-depth: a direct `enqueue` of a destructive kind WITH
    /// both factors succeeds and reaches the ports.
    #[tokio::test]
    async fn enqueue_destructive_allowed_with_claim_reaches_ports() {
        let job_id = Uuid::new_v4();
        let jobs = Arc::new(RecordingJobsRepository::new(job_id));
        let events = Arc::new(RecordingEventStore::new());
        let use_case = TaskUseCase::new(
            Arc::clone(&jobs) as _,
            crate::event_store_publisher::wrap_for_test(Arc::clone(&events)),
            rbac_with_task_invoke(),
        );
        let actor = caller_with_destructive_claim();
        let result = use_case
            .enqueue(&actor, "retention-purge", &serde_json::json!({}), None)
            .await;
        assert_eq!(
            result.expect("destructive enqueue should succeed"),
            EnqueueOutcome::Enqueued { job_id }
        );
        assert_eq!(jobs.enqueue_calls().len(), 1);
        assert_eq!(events.append_calls().len(), 1);
    }

    // -- Destructive-kind TaskInvoked audit-stream routing --

    /// `task_audit_stream`: each of the three destructive kinds — the
    /// closed `DESTRUCTIVE_TASK_KINDS` set from the domain helper — routes
    /// to the never-deleted `eventstore_retention()` audit-meta stream so
    /// an `eventstore-archive`/`retention-purge` cannot truncate its own
    /// invocation trail.
    #[test]
    fn task_audit_stream_destructive_kinds_route_to_eventstore_retention() {
        let exempt = StreamId::eventstore_retention();
        for kind in [
            "retention-purge",
            "eventstore-archive",
            "retention-evaluate",
        ] {
            assert_eq!(
                TaskUseCase::task_audit_stream(kind),
                exempt,
                "destructive kind {kind:?} must route to the exempt audit-meta stream"
            );
        }
    }

    /// `task_audit_stream`: representative non-destructive kinds AND
    /// unrecognised strings route to `authorization()` (fail-safe — an
    /// unknown input must never be treated as destructive).
    #[test]
    fn task_audit_stream_non_destructive_and_unknown_route_to_authorization() {
        let authz = StreamId::authorization();
        for kind in ["noop", "scan", "staging-sweep", "", "totally-unknown-kind"] {
            assert_eq!(
                TaskUseCase::task_audit_stream(kind),
                authz,
                "non-destructive/unknown kind {kind:?} must route to the authorization stream"
            );
        }
    }

    /// End-to-end: a destructive-kind `enqueue` appends `TaskInvoked` on
    /// `eventstore_retention()` (not `authorization()`).
    #[tokio::test]
    async fn enqueue_destructive_appends_taskinvoked_on_eventstore_retention() {
        let job_id = Uuid::new_v4();
        let jobs = Arc::new(RecordingJobsRepository::new(job_id));
        let events = Arc::new(RecordingEventStore::new());
        let use_case = TaskUseCase::new(
            Arc::clone(&jobs) as _,
            crate::event_store_publisher::wrap_for_test(Arc::clone(&events)),
            rbac_with_task_invoke(),
        );
        let actor = caller_with_destructive_claim();
        use_case
            .enqueue(&actor, "eventstore-archive", &serde_json::json!({}), None)
            .await
            .expect("destructive enqueue should succeed");

        let append_calls = events.append_calls();
        assert_eq!(append_calls.len(), 1);
        let batch = &append_calls[0].batch;
        assert_eq!(
            batch.stream_id,
            StreamId::eventstore_retention(),
            "destructive TaskInvoked must land on the exempt audit-meta stream"
        );
        assert!(matches!(batch.events[0].event, DomainEvent::TaskInvoked(_)));
    }

    /// No regression: a non-destructive `enqueue` still appends
    /// `TaskInvoked` on the `authorization()` stream.
    #[tokio::test]
    async fn enqueue_non_destructive_still_appends_taskinvoked_on_authorization() {
        let job_id = Uuid::new_v4();
        let jobs = Arc::new(RecordingJobsRepository::new(job_id));
        let events = Arc::new(RecordingEventStore::new());
        let use_case = TaskUseCase::new(
            Arc::clone(&jobs) as _,
            crate::event_store_publisher::wrap_for_test(Arc::clone(&events)),
            rbac_with_task_invoke(),
        );
        let actor = caller_with_task_admin_role();
        use_case
            .enqueue(&actor, "noop", &serde_json::json!({}), None)
            .await
            .expect("non-destructive enqueue should succeed");

        let append_calls = events.append_calls();
        assert_eq!(append_calls.len(), 1);
        assert_eq!(
            append_calls[0].batch.stream_id,
            StreamId::authorization(),
            "non-destructive TaskInvoked must remain on the authorization stream"
        );
    }

    // -- idempotency_key thread-through (ADR 0028) ---------------------------

    /// `TaskUseCase::enqueue` threads `Some(idempotency_key)` through to
    /// `JobsRepository::enqueue_task` unchanged. Pins the "use case makes
    /// no decision about destructive-vs-not" contract —
    /// the handler owns the classification.
    #[tokio::test]
    async fn enqueue_threads_idempotency_key_through_to_port() {
        let job_id = Uuid::new_v4();
        let jobs = Arc::new(RecordingJobsRepository::new(job_id));
        let events = Arc::new(RecordingEventStore::new());
        let use_case = TaskUseCase::new(
            Arc::clone(&jobs) as _,
            crate::event_store_publisher::wrap_for_test(Arc::clone(&events)),
            rbac_with_task_invoke(),
        );

        let key = IdempotencyKey::try_from("cron:noop:2026-06-03").expect("valid");
        let actor = caller_with_task_admin_role();
        let outcome = use_case
            .enqueue(&actor, "noop", &serde_json::json!({}), Some(&key))
            .await
            .expect("enqueue with idempotency key should succeed");
        assert_eq!(outcome, EnqueueOutcome::Enqueued { job_id });

        let calls = jobs.enqueue_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].idempotency_key.as_ref(),
            Some(&key),
            "use case must thread the key straight through"
        );
    }

    /// `TaskUseCase::enqueue` MUST emit `TaskInvoked` on the `Duplicate`
    /// branch too, with `duplicate_of = Some(existing_job_id)` flagging
    /// the dedup hit. `task_job_id` carries the existing row's id (the
    /// row that was logically enqueued). The use case still passes the
    /// outcome through verbatim and does NOT compensate-delete the
    /// existing row.
    #[tokio::test]
    async fn enqueue_duplicate_outcome_emits_taskinvoked_with_duplicate_of_some() {
        let existing_id = Uuid::new_v4();
        let jobs = Arc::new(RecordingJobsRepository::with_duplicate(existing_id));
        let events = Arc::new(RecordingEventStore::new());
        let use_case = TaskUseCase::new(
            Arc::clone(&jobs) as _,
            crate::event_store_publisher::wrap_for_test(Arc::clone(&events)),
            rbac_with_task_invoke(),
        );

        let key = IdempotencyKey::try_from("cron:noop:2026-06-03").expect("valid");
        let actor = caller_with_task_admin_role();
        let outcome = use_case
            .enqueue(&actor, "noop", &serde_json::json!({}), Some(&key))
            .await
            .expect("duplicate outcome must surface as Ok");
        assert_eq!(
            outcome,
            EnqueueOutcome::Duplicate {
                existing_job_id: existing_id
            },
            "use case must pass through the Duplicate outcome verbatim"
        );

        // TaskInvoked IS emitted on the Duplicate branch.
        let append_calls = events.append_calls();
        assert_eq!(
            append_calls.len(),
            1,
            "Duplicate branch must emit TaskInvoked"
        );
        let batch = &append_calls[0].batch;
        let DomainEvent::TaskInvoked(payload) = &batch.events[0].event else {
            panic!("expected TaskInvoked, got something else");
        };
        assert_eq!(
            payload.task_job_id, existing_id,
            "TaskInvoked.task_job_id must be the existing row's id on Duplicate"
        );
        assert_eq!(
            payload.duplicate_of,
            Some(existing_id),
            "TaskInvoked.duplicate_of must be Some(existing_id) on Duplicate"
        );

        // And no compensating delete — the existing row is not ours to
        // remove.
        assert_eq!(
            jobs.delete_calls().len(),
            0,
            "Duplicate branch must NOT compensate-delete"
        );
    }

    /// The fresh-enqueue branch emits
    /// `TaskInvoked` with `duplicate_of = None` (the baseline shape).
    #[tokio::test]
    async fn enqueue_fresh_outcome_emits_taskinvoked_with_duplicate_of_none() {
        let job_id = Uuid::new_v4();
        let jobs = Arc::new(RecordingJobsRepository::new(job_id));
        let events = Arc::new(RecordingEventStore::new());
        let use_case = TaskUseCase::new(
            Arc::clone(&jobs) as _,
            crate::event_store_publisher::wrap_for_test(Arc::clone(&events)),
            rbac_with_task_invoke(),
        );

        let actor = caller_with_task_admin_role();
        let outcome = use_case
            .enqueue(&actor, "noop", &serde_json::json!({}), None)
            .await
            .expect("fresh enqueue must succeed");
        assert_eq!(outcome, EnqueueOutcome::Enqueued { job_id });

        let append_calls = events.append_calls();
        assert_eq!(append_calls.len(), 1);
        let DomainEvent::TaskInvoked(payload) = &append_calls[0].batch.events[0].event else {
            panic!("expected TaskInvoked, got something else");
        };
        assert_eq!(payload.task_job_id, job_id);
        assert_eq!(
            payload.duplicate_of, None,
            "TaskInvoked.duplicate_of must be None on the fresh-enqueue branch"
        );
    }
}
