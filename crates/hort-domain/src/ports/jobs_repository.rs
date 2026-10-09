//! Outbound port for the cross-kind `jobs` table (migration 009).
//!
//! This port is the data-access seam for the scan
//! orchestrator: claim a batch of `kind='scan'` rows via
//! `FOR UPDATE SKIP LOCKED`, then mark them completed / rescheduled /
//! permanently failed as the worker progresses through `run_scan` and
//! `record_outcome`.
//!
//! The generalised admin-task framework
//! reuses the same port and the same row shape for the other
//! seven `kind` values (`'cron-rescan-tick'`, `'advisory-watch-tick'`,
//! `'retention-evaluate'`, `'retention-purge'`, `'eventstore-archive'`,
//! `'staging-sweep'`, `'noop'`). The scan orchestrator only consumes the
//! scan-job subset (`claim_scan_jobs`, `mark_completed`, `reschedule`,
//! `mark_failed`); `enqueue_scan` is exposed for the ingest
//! integration and worker-test fixtures.
//!
//! The Postgres adapter lives in `hort-adapters-postgres::jobs_repository`.
//! The schema is defined in `migrations/009_scan_jobs_and_findings.sql`.
//!
//! See `docs/architecture/explanation/scanning-pipeline.md` and
//! ADR 0028 (destructive-task idempotency).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;

use crate::error::{DomainError, DomainResult};
use crate::types::{ContentHash, IdempotencyKey};

use super::BoxFuture;

/// Outcome of [`JobsRepository::enqueue_task`].
///
/// `Enqueued` — the insert went through, returning the new row's id.
/// `Duplicate` — the `idempotency_key` partial-unique index matched an
/// existing row; no new row was inserted, and the existing row's id is
/// returned. See ADR 0028 (destructive-task idempotency).
///
/// The handler maps `Duplicate` to a 200 response with the existing job
/// id; the use case emits the `TaskInvoked` audit event on both
/// branches, with `duplicate_of` flagging the dedup hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Fresh insert. `job_id` is the newly-created row's id.
    Enqueued { job_id: Uuid },
    /// `idempotency_key` collided with an existing row's claim.
    /// `existing_job_id` is the existing row's id.
    Duplicate { existing_job_id: Uuid },
}

/// Lifecycle status of a row in the `jobs` table.
///
/// Mirrors the SQL CHECK constraint
/// `status IN ('pending', 'running', 'completed', 'failed')`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    /// Available for a worker to claim.
    Pending,
    /// Claimed by a worker; `locked_by` and `locked_until` are populated.
    Running,
    /// Terminal success.
    Completed,
    /// Terminal failure (after exhausting retries).
    Failed,
}

impl JobStatus {
    /// Wire shape — must match the SQL CHECK literals.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// Why a `kind='scan'` (or other-kind) row exists.
///
/// Mirrors the SQL CHECK constraint
/// `trigger_source IN ('manual', 'cron', 'advisory', 'ingest')`
/// in migration 009. Each source maps to a fixed priority ranking:
///
/// | `TriggerSource` | priority | Set by | Rationale |
/// |---|---|---|---|
/// | `Manual`   | 20 | `ManualRescanUseCase` | Operator clicked "rescan now"; jump the queue. |
/// | `Cron`     | 10 | `CronRescanTickHandler` | Routine background drain. |
/// | `Advisory` | 5  | `AdvisoryWatchTickHandler` | Targeted; below cron (the safety-net path). |
/// | `Ingest`   | 0  | `IngestUseCase` | First-scan happens at ingest; FIFO is fine. |
///
/// **Wire literals must match the SQL CHECK exactly.** The watch
/// tick's source is `"advisory"`, NOT `"advisory_watch"` —
/// [`FromStr`] rejects the underscored form to prevent silent
/// observability mis-categorisation (a label drifted from the SQL
/// CHECK would either get rejected at INSERT time or, worse, get
/// silently filed under the wrong bucket if a future migration
/// loosened the CHECK without updating this enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TriggerSource {
    /// First-scan at ingest. Default priority 0.
    Ingest,
    /// Cron rescan tick handler. Default priority 10.
    Cron,
    /// Advisory watch tick handler. Default priority 5.
    Advisory,
    /// Operator-triggered manual rescan. Default priority 20.
    Manual,
}

impl TriggerSource {
    /// Wire shape — must match the SQL CHECK literals exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::Cron => "cron",
            Self::Advisory => "advisory",
            Self::Manual => "manual",
        }
    }
}

impl fmt::Display for TriggerSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TriggerSource {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ingest" => Ok(Self::Ingest),
            "cron" => Ok(Self::Cron),
            "advisory" => Ok(Self::Advisory),
            "manual" => Ok(Self::Manual),
            other => Err(DomainError::Validation(format!(
                "unknown trigger_source {other:?} (expected one of \
                 'ingest' | 'cron' | 'advisory' | 'manual')"
            ))),
        }
    }
}

/// Filter parameters for [`JobsRepository::list_jobs`].
///
/// Both fields are optional — `None` means "no filtering on that axis".
/// Passing `None` for both returns all jobs across all kinds and statuses
/// (subject to the pagination limit).
#[derive(Debug, Clone, Default)]
pub struct ListJobsFilter {
    /// When `Some`, restrict to rows matching this `kind` literal.
    pub kind: Option<String>,
    /// When `Some`, restrict to rows matching this `status`.
    pub status: Option<JobStatus>,
}

/// A page of jobs returned by [`JobsRepository::list_jobs`].
#[derive(Debug, Clone)]
pub struct ListJobsPage {
    /// Rows in descending `id` order (most-recently-inserted first).
    pub items: Vec<JobRow>,
    /// When `Some`, the caller may pass this as `cursor` to retrieve the
    /// next page. `None` means this is the last page.
    pub next_cursor: Option<Uuid>,
}

/// Generic cross-kind projection of a row in the `jobs` table.
///
/// Used by the `list_jobs` / `get_job` read paths and
/// by the `TaskDispatcher`'s `claim_pending_by_kinds` path.
/// Scan-specific callers continue to use [`ScanJob`] via `claim_scan_jobs`.
///
/// Kind-specific typed columns live in [`KindFields`]. For `kind='scan'`
/// rows the four `artifact_id` / `repository_id` / `content_hash` /
/// `format` columns are schema-level invariants (NOT NULL via the
/// migration-009 CHECK constraint), so the adapter projects them into
/// [`KindFields::Scan`] with non-optional fields. A row mapper that
/// receives `kind='scan'` without those columns refuses to construct
/// the row — see `decide_kind_fields` in the Postgres adapter. This is
/// load-bearing: a previous shape used `Option<T>` per field, and a
/// missing-column-in-RETURNING bug silently decoded as four `None`s,
/// taking the entire scan pipeline down because the
/// `ScanTaskHandler` rejected every claimed row.
#[derive(Debug, Clone)]
pub struct JobRow {
    pub id: Uuid,
    pub kind: String,
    pub status: JobStatus,
    /// Deserialized params JSONB. `None` means the column was SQL NULL
    /// (not expected in practice; defensive to avoid Invariant errors).
    pub params: Option<serde_json::Value>,
    pub actor_id: Option<Uuid>,
    pub priority: i16,
    pub trigger_source: String,
    pub attempts: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    /// Deserialized `result_summary` JSONB — the handler's
    /// `TaskOutcome::Completed { result_summary }`. `None` when the column
    /// is SQL NULL (no summary). A structured value, NOT a string: the
    /// column is `jsonb`, so this mirrors [`Self::params`].
    pub result_summary: Option<serde_json::Value>,
    /// Kind-specific typed projection. See [`KindFields`].
    pub kind_fields: KindFields,
}

/// Kind-specific typed projection on a [`JobRow`].
///
/// The sum-type shape replaces four parallel `Option<T>` fields. The
/// previous shape conflated three distinct cases — "this kind doesn't
/// carry these columns", "this kind carries them and they were
/// populated", and "this kind carries them but the query forgot to
/// project them" — and the third case produced a silent NULL the
/// scan handler then had to defensively `ok_or_else` 30 lines
/// downstream. Encoding the typed columns as a non-optional inner
/// struct moves the check to the row-mapper boundary, where a missing
/// column becomes a loud `DomainError::Invariant` instead of a NULL
/// the dispatcher later choke on.
#[derive(Debug, Clone, PartialEq)]
pub enum KindFields {
    /// `kind='scan'` projection. All four columns are non-NULL by
    /// migration-009 invariants; the adapter refuses to build this
    /// variant from a partial row.
    Scan(ScanKindFields),
    /// Kinds without a typed scan-shaped projection
    /// (`staging-sweep`, `noop`, `cron-rescan-tick`,
    /// `advisory-watch-tick`, `service-account-rotation`, …).
    Other,
}

impl KindFields {
    /// Return the inner scan projection if this is a scan-kind row.
    pub fn as_scan(&self) -> Option<&ScanKindFields> {
        match self {
            Self::Scan(s) => Some(s),
            Self::Other => None,
        }
    }
}

/// Typed projection of the four scan-specific columns on `jobs` for
/// `kind='scan'` rows.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanKindFields {
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub content_hash: ContentHash,
    pub format: String,
}

/// One kind's claim-eligible pending backlog, as observed by
/// [`JobsRepository::eligible_pending_by_kind`].
///
/// "Claim-eligible" means the row satisfies every predicate of the
/// multi-kind claim query EXCEPT the `kind = ANY(<registered kinds>)`
/// filter: `status = 'pending'` and
/// `(locked_until IS NULL OR locked_until < now())`. Deliberately
/// unfiltered by kind — the starvation audit's whole purpose is to see
/// backlogs the poll loop's own kind array cannot (the blind spot: the
/// `provenance-verify` handler was not registered, so the claim query
/// never selected the kind and ~1450 rows accumulated with zero
/// diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingKindBacklog {
    /// The `jobs.kind` value.
    pub kind: String,
    /// Number of claim-eligible pending rows of this kind.
    pub count: i64,
    /// `created_at` of the oldest claim-eligible pending row of this kind.
    pub oldest_created_at: DateTime<Utc>,
}

/// Domain projection of a `kind='scan'` row in the `jobs` table.
///
/// Carries the typed scan-specific columns
/// (`artifact_id`, `repository_id`, `content_hash`, `format`) plus the
/// shared lifecycle columns. Cross-kind rows surfaced via the same port
/// use a different domain projection ([`JobRow`]) — this struct is
/// scan-only.
///
/// `trigger_source` and `priority` mirror the columns migration 009
/// shipped on the `jobs` table. `trigger_source` is
/// the metric label on
/// `hort_scan_jobs_enqueued_total{trigger_source}` and the
/// audit-trail signal answering "why does this scan exist?". The
/// adapter-side `claim_scan_jobs` query already orders by
/// `priority DESC, created_at ASC` — `priority` is surfaced here so
/// callers and tests can observe the bucket the row was claimed in
/// without re-reading the row.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanJob {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub content_hash: ContentHash,
    pub format: String,
    pub status: JobStatus,
    pub attempts: u32,
    pub locked_by: Option<String>,
    pub locked_until: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Why this scan was scheduled. Maps to the `trigger_source`
    /// column on the `jobs` table.
    pub trigger_source: TriggerSource,
    /// Claim ordering bucket. Maps to the `priority` column on the
    /// `jobs` table (CHECK `BETWEEN 0 AND 100`). Stored as `u8`
    /// because the CHECK constraint already bounds the range below
    /// `u8::MAX`; the adapter validates at the row-mapper boundary.
    pub priority: u8,
}

// ---------------------------------------------------------------------------
// Abandoned-lease requeue policy
// ---------------------------------------------------------------------------

/// What the abandoned-lease sweep did to one row it found stranded in
/// `running` with a lapsed lease.
///
/// The sweep is the only actor that runs when a handler never returns,
/// so it is also the only place the retry budget can be enforced for
/// that row — see [`JobsRepository::requeue_abandoned`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequeueOutcome {
    /// `running` → `pending`. The row is claimable again.
    Requeued,
    /// `running` → `failed`. `attempts` had already reached the cap, so
    /// requeueing again would loop forever behind a task that kills its
    /// worker every time. The row is retained (not deleted) so a late
    /// completion from the original worker still lands somewhere.
    RetriesExhausted,
}

/// One row the abandoned-lease sweep resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequeuedJob {
    pub id: Uuid,
    pub kind: String,
    /// `attempts` as it stood when the sweep resolved the row. The sweep
    /// does NOT touch the counter — the next claim increments it, exactly
    /// as it does for a `reschedule`d row.
    pub attempts: u32,
    pub outcome: RequeueOutcome,
}

/// Task kinds whose abandoned `running` rows the lease-expiry sweep
/// returns to `pending`.
///
/// A requeue can put two executions of the same row in flight at once:
/// lease renewal makes that require a worker that stopped renewing and
/// then resumed (a paused container, a long DB partition), but it does
/// not make it impossible. Membership here is therefore a statement that
/// **concurrent self-execution of the kind is absorbed by a mechanism
/// that already exists**, not that concurrency is unlikely:
///
/// - `scan` — the verdict commit is a compare-and-set on the prior
///   quarantine status (`commit_scan_result_with_score`'s `prior_status`)
///   inside the event append's expected-version transaction, so the
///   loser of a race rolls back whole, findings included. Requeue is
///   load-bearing here and nowhere else as sharply: `jobs_scan_unique`
///   is `(artifact_id) WHERE kind='scan' AND status IN
///   ('pending','running')`, so an abandoned row makes its artifact
///   permanently unscannable AND unrescannable.
/// - `provenance-verify` — same in-flight trap via
///   `find_active_provenance_for_artifact`; the verdict application
///   rides the same optimistic-concurrency transition path.
/// - `prefetch` / `prefetch-dependencies` — same trap via
///   `jobs_prefetch_unique` / `jobs_prefetch_dependencies_unique` on
///   `target_key`. Duplicate work is absorbed by the L2 terminal-ingest
///   absorb (the `artifacts` path-UNIQUE) and L3 (`ON CONFLICT
///   (target_key) DO NOTHING`), which the cascade already relies on for
///   the prefetch-vs-client-pull race.
/// - `cron-rescan-tick` / `advisory-watch-tick` / `prefetch-tick` —
///   candidate selection plus an enqueue whose duplicate is rejected by
///   a partial unique index.
/// - `quarantine-release-sweep` — re-evaluates the fail-closed release
///   predicate per artifact and commits through the same
///   optimistic-concurrency transition.
/// - `policy-reevaluation` — documented verdict-idempotent with
///   event-version optimistic concurrency (ADR 0041 Item 3).
/// - `replay-seen-prune`, `scanner-registry-prune`,
///   `prefetch-row-retention-sweep`, `scan-row-retention-sweep`,
///   `jobs-row-retention-sweep`, `staging-sweep` — `DELETE` over a
///   predicate: running the set operation twice reaches the same set.
/// - `oci-index-child-ingest`, `oci-membership-edge-backfill`,
///   `wheel-metadata-backfill` — content-addressed ingest / edge
///   re-derivation / metadata backfill, all upsert- or CAS-shaped.
/// - `noop` — a pure function of `params`.
///
/// Disjoint from [`NO_REQUEUE_ON_LEASE_EXPIRY_KINDS`], and their union is
/// exactly `EVENT_TASK_KINDS`. The
/// [`requeue_policy_is_exhaustive_over_event_task_kinds`] test is what
/// makes a future `jobs.kind` a compile-and-test failure until someone
/// classifies it, rather than a kind that silently inherits either
/// behaviour.
pub const REQUEUE_ON_LEASE_EXPIRY_KINDS: &[&str] = &[
    "scan",
    "provenance-verify",
    "prefetch",
    "prefetch-dependencies",
    "prefetch-tick",
    "cron-rescan-tick",
    "advisory-watch-tick",
    "quarantine-release-sweep",
    "policy-reevaluation",
    "replay-seen-prune",
    "scanner-registry-prune",
    "prefetch-row-retention-sweep",
    "scan-row-retention-sweep",
    "jobs-row-retention-sweep",
    "staging-sweep",
    "oci-index-child-ingest",
    "oci-membership-edge-backfill",
    "wheel-metadata-backfill",
    "noop",
];

/// Task kinds the lease-expiry sweep leaves in `running`.
///
/// Every kind here shares two properties, and both are required for the
/// exclusion to be free:
///
/// 1. **A concurrent second execution is not absorbed by anything.**
/// 2. **An abandoned row blocks nothing.** None of these kinds appears in
///    an `status IN ('pending','running')` uniqueness index or read, so
///    the stranded row is one clutter row; the kind's next scheduled tick
///    enqueues a fresh row and the work happens. Exclusion costs a row,
///    not a capability — which is exactly why the trade goes this way.
///
/// Per kind:
///
/// - `eventstore-archive` — `seal_and_remove`'s `StreamSealed` append to
///   `admin-eventstore-retention` has no internal wait bound and is safe
///   only because at most one is in flight cluster-wide. The three layers
///   that deliver that are the CronJob's `concurrencyPolicy: Forbid`, the
///   worker's per-kind semaphore, and the per-UTC-day idempotency key —
///   and the semaphore is per *process*. A requeue claimed by a sibling
///   replica walks around all three. Relaxing this needs a security
///   co-review, not a sweep (ADR 0020, ADR 0028).
/// - `retention-purge` — destructive storage GC, and it fires the
///   pre-purge checkpoint hook before deleting. Two concurrent walks race
///   on refcounts and emit two checkpoints.
/// - `retention-evaluate` — drives the two above.
/// - `eventstore-checkpoint` — derives the next `checkpoint_seq` as
///   `max(existing) + 1` by reading then writing. Two concurrent
///   emissions derive the same sequence number.
/// - `service-account-rotation` — the freshness gate is a read of the k8s
///   Secret annotation followed by a mint + upsert. Two concurrent ticks
///   both read stale, both mint, and the losing upsert leaves a live PAT
///   carrying the account's full declared permissions that no Secret
///   references. Every 15 minutes, so the next tick recovers.
/// - `seed-import` — an operator one-shot that bulk-registers with
///   backdated quarantine anchors; a concurrent second pass can register
///   past its own already-imported check. The operator re-runs the
///   subcommand.
/// - `verify-event-chain` — not worker-dispatched at all. The
///   `hort-server verify-event-chain` subcommand writes the row as a
///   completed liveness breadcrumb, so it is never claimed and never
///   `running`. Listed so the exhaustiveness guard has a home for it.
pub const NO_REQUEUE_ON_LEASE_EXPIRY_KINDS: &[&str] = &[
    "eventstore-archive",
    "retention-purge",
    "retention-evaluate",
    "eventstore-checkpoint",
    "service-account-rotation",
    "seed-import",
    "verify-event-chain",
];

/// Outbound port for the `jobs` table — scan-job subset.
///
/// `claim_scan_jobs` is the leader-electing read: each worker calls it
/// once per poll-tick, batches the returned rows through `run_scan`,
/// then closes them out via `mark_completed` / `reschedule` /
/// `mark_failed`. The Postgres adapter ships the
/// `FOR UPDATE SKIP LOCKED` claim query; mocks
/// simulate the same semantics with their own data structure.
///
/// `enqueue_scan` is exposed so the ingest path can insert a
/// `kind='scan'` row inside the same Postgres transaction as
/// `ArtifactIngested` + `ScanRequested`. The scan
/// orchestrator does NOT call `enqueue_scan` — that wiring belongs to
/// the worker / ingest integration.
pub trait JobsRepository: Send + Sync {
    /// Claim up to `batch_size` `kind='scan'` rows whose
    /// `(locked_until IS NULL OR locked_until < now())`. Marks each
    /// claimed row `running`, increments `attempts`, sets `locked_by`
    /// and `locked_until = now() + lock_duration`. Returns the rows in
    /// their post-update state.
    ///
    /// `worker_id` becomes `locked_by`. When a worker pod dies
    /// mid-scan, its claim expires after `lock_duration` and another
    /// worker re-claims the row.
    fn claim_scan_jobs<'a>(
        &'a self,
        worker_id: &'a str,
        batch_size: u32,
        lock_duration: Duration,
    ) -> BoxFuture<'a, DomainResult<Vec<ScanJob>>>;

    /// Mark `job_id` as `completed` and persist `result_summary` — the
    /// handler's `TaskOutcome::Completed { result_summary }` (H15/H17).
    /// A `Value::Null` summary is stored as SQL NULL (the "no summary"
    /// sentinel). Idempotent — a row already in `completed` state takes
    /// the update without error.
    fn mark_completed<'a>(
        &'a self,
        job_id: Uuid,
        result_summary: serde_json::Value,
    ) -> BoxFuture<'a, DomainResult<()>>;

    /// Reschedule a transient failure. Status stays `pending`,
    /// `locked_by` and `locked_until` are cleared and reset to
    /// `now() + backoff`, and `last_error` records the failure
    /// message for operator visibility.
    fn reschedule<'a>(
        &'a self,
        job_id: Uuid,
        backoff: Duration,
        last_error: &'a str,
    ) -> BoxFuture<'a, DomainResult<()>>;

    /// Permanently fail a job — `status='failed'`, `last_error=err`.
    /// Terminal: no further claim attempts.
    fn mark_failed<'a>(
        &'a self,
        job_id: Uuid,
        last_error: &'a str,
    ) -> BoxFuture<'a, DomainResult<()>>;

    /// Insert a fresh `kind='scan'` row for an artifact. The partial
    /// unique on `(artifact_id) WHERE kind='scan' AND artifact_id IS
    /// NOT NULL` enforces at-most-one; duplicate inserts surface as
    /// `DomainError::Conflict`. Returns the inserted row's id.
    fn enqueue_scan<'a>(
        &'a self,
        artifact_id: Uuid,
        repository_id: Uuid,
        content_hash: &'a ContentHash,
        format: &'a str,
        priority: i16,
        trigger_source: &'a str,
    ) -> BoxFuture<'a, DomainResult<Uuid>>;

    /// Count `kind='scan'` rows whose status is `pending` — the
    /// "queue depth" signal emitted as `hort_scan_queue_depth`.
    /// `running` rows are excluded because they are already being
    /// worked on; `completed` and `failed` rows are terminal.
    ///
    /// Default impl returns `Ok(0)` so test fixtures (mocks in
    /// `hort-app::use_cases::scan_orchestration_tests`) that pre-date the
    /// method continue to compile without modification. The Postgres
    /// adapter overrides with the real query.
    fn pending_scan_count<'a>(&'a self) -> BoxFuture<'a, DomainResult<i64>> {
        Box::pin(async { Ok(0) })
    }

    /// Return the id of an in-flight `kind='scan'`
    /// row for `artifact_id`, where "in-flight" means
    /// `status IN ('pending', 'running')`. Returns `Ok(None)` when no
    /// such row exists.
    ///
    /// Used by [`crate::ports::jobs_repository::JobsRepository`] callers
    /// that need to differentiate "scan already enqueued / running for
    /// this artifact" from "scan completed long ago" — the partial
    /// unique index on `(artifact_id) WHERE kind='scan'` cannot
    /// distinguish the two on its own. The manual-rescan REST endpoint
    /// surfaces the in-flight case as `409 Conflict`; a completed-status
    /// row is allowed to be re-enqueued (re-scan workflow).
    ///
    /// **Default implementation:** returns `Ok(None)` so existing test
    /// fixtures (mocks in `hort-app::use_cases::scan_orchestration_tests`
    /// and the `MockJobsRepository` in `test_support`) compile without
    /// modification. Tests that exercise the in-flight conflict path
    /// override this method or seed via the `MockJobsRepository`'s
    /// dedicated helper.
    fn find_active_scan_for_artifact<'a>(
        &'a self,
        artifact_id: Uuid,
    ) -> BoxFuture<'a, DomainResult<Option<Uuid>>> {
        let _ = artifact_id;
        Box::pin(async { Ok(None) })
    }

    /// Return the id of an in-flight `kind='provenance-verify'` row for
    /// `artifact_id`, where "in-flight" means `status IN
    /// ('pending','running')`. Returns `Ok(None)` when no such row
    /// exists.
    ///
    /// Mirrors [`Self::find_active_scan_for_artifact`] for the provenance
    /// pipeline. Unlike the `kind='scan'` rows, a `provenance-verify` row
    /// carries its `artifact_id` in the `params` JSONB (`{"artifact_id":
    /// …}`), not the scan-typed `artifact_id` column — the Postgres
    /// adapter matches on `params->>'artifact_id'`. There is no partial-
    /// unique index for provenance-verify, so this read is the dedup
    /// mechanism the expiry backstop
    /// ([`QuarantineUseCase::release_expired`](crate)) uses to avoid
    /// piling up duplicate open jobs for the same `Pending` candidate
    /// across sweep ticks.
    ///
    /// **Default implementation:** returns `Ok(None)` so existing test
    /// fixtures (mocks in `hort-app::use_cases::scan_orchestration_tests`
    /// and the `MockJobsRepository` in `test_support`) compile without
    /// modification (same additive-default pattern as
    /// [`Self::find_active_scan_for_artifact`]). A `None` default means
    /// "no in-flight verify seen" — fail-safe for a mock that does not
    /// override it (the backstop enqueues rather than silently skipping).
    fn find_active_provenance_for_artifact<'a>(
        &'a self,
        artifact_id: Uuid,
    ) -> BoxFuture<'a, DomainResult<Option<Uuid>>> {
        let _ = artifact_id;
        Box::pin(async { Ok(None) })
    }

    /// Extend the claim lease on a row this worker is currently running.
    ///
    /// `UPDATE … SET locked_until = now() + lock_duration WHERE id =
    /// job_id AND locked_by = worker_id AND status = 'running'`. Returns
    /// `true` when exactly that row was updated and `false` when it was
    /// not — the row has already been closed out, or an abandoned-lease
    /// sweep decided this worker was dead and handed the row on. `false`
    /// is therefore a **fencing signal**: whatever the caller is running
    /// against that row is no longer the authoritative execution.
    ///
    /// This is what makes [`Self::requeue_abandoned`]'s discriminator
    /// mean anything. Without renewal, `locked_until < now()` on a
    /// `running` row says only "the task outlived the claim's nominal
    /// lease", which is equally true of a dead worker and of a slow one.
    /// With a renewal every `lock_duration / 3`, a lapsed lease means
    /// three consecutive renewals failed to land, which a live worker
    /// with a working database connection does not do.
    ///
    /// **Default implementation:** returns `Ok(true)`. A mock has no
    /// lease to extend, and the honest answer for "is the fixture's row
    /// still mine" is yes — the additive-default pattern of
    /// [`Self::find_active_scan_for_artifact`].
    fn renew_lease<'a>(
        &'a self,
        job_id: Uuid,
        worker_id: &'a str,
        lock_duration: Duration,
    ) -> BoxFuture<'a, DomainResult<bool>> {
        let _ = (job_id, worker_id, lock_duration);
        Box::pin(async { Ok(true) })
    }

    /// Resolve up to `batch_size` rows stranded in `running` whose lease
    /// lapsed more than `grace` ago, restricted to `kinds`.
    ///
    /// A row with `attempts < attempt_cap` goes back to `pending` with
    /// `locked_by` cleared and `locked_until` set to a short not-before
    /// so the same replica does not re-grab it on the very next tick
    /// ([`RequeueOutcome::Requeued`]). A row at or above the cap goes to
    /// `failed` ([`RequeueOutcome::RetriesExhausted`]).
    ///
    /// **The cap has to be enforced here, because for a row whose
    /// handler never returned this is the only place it can be.** Every
    /// other place the same budget is spent runs *after* the handler
    /// returns — the scan orchestrator's `attempts >= max_attempts`
    /// branch in `record_outcome`, the dispatcher's
    /// `TaskOutcome::Failed { retry }` arm. A task that kills its worker
    /// never reaches any of them, so a requeue that did not carry its
    /// own cap would re-drive a crash loop forever while `attempts`
    /// climbed with nothing reading it. The number is the same on every
    /// path on purpose; the dispatcher's `JOB_ATTEMPT_CAP` is what it
    /// passes in here.
    ///
    /// The row is never deleted. It may be genuinely running, and its
    /// completion has to land somewhere: `mark_completed` /
    /// `mark_failed` are unconditional on `id`, so a late write from the
    /// original worker still updates the surviving row instead of
    /// silently updating nothing.
    ///
    /// `attempts` is left alone. The claim increments it, so a requeued
    /// row is counted on its next claim exactly like a `reschedule`d
    /// one — the sweep spends no budget of its own.
    ///
    /// `kinds` is expected to be [`REQUEUE_ON_LEASE_EXPIRY_KINDS`]; see
    /// that constant for why the complement is excluded.
    ///
    /// **Default implementation:** returns `Ok(vec![])` — "this
    /// repository has no abandoned-row recovery", the same additive
    /// default [`Self::pending_scan_count`] uses.
    fn requeue_abandoned<'a>(
        &'a self,
        kinds: &'a [&'a str],
        grace: Duration,
        attempt_cap: u32,
        batch_size: u16,
    ) -> BoxFuture<'a, DomainResult<Vec<RequeuedJob>>> {
        let _ = (kinds, grace, attempt_cap, batch_size);
        Box::pin(async { Ok(Vec::new()) })
    }
    /// Insert a cross-kind `jobs` row with `status='pending'`.
    ///
    /// Used by `TaskUseCase::enqueue` to create
    /// admin-task rows for any of the v1 `kind` values
    /// (`scan`, `cron-rescan-tick`, `advisory-watch-tick`,
    /// `retention-evaluate`, `retention-purge`, `eventstore-archive`,
    /// `staging-sweep`, `noop`).
    ///
    /// When `idempotency_key` is `Some(k)` the adapter runs an
    /// `ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL
    /// DO NOTHING` insert against the `jobs_idempotency_key_uq`
    /// partial-unique index (migration 009). If the key matches an
    /// existing row, no new row is inserted and the adapter returns
    /// [`EnqueueOutcome::Duplicate`] with the existing row's id —
    /// preserving the prior enqueue's audit chain rather than emitting a
    /// fresh `TaskInvoked` (ADR 0028).
    /// `None` preserves today's behaviour exactly: the partial-unique
    /// predicate is inert, the insert always proceeds, and the result is
    /// always [`EnqueueOutcome::Enqueued`].
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("not implemented"))` so existing test
    /// fixtures (mocks in `hort-app::use_cases::scan_orchestration_tests`)
    /// that pre-date this method continue to compile without modification.
    /// Tests that exercise `enqueue_task` override this method in their
    /// mock.
    fn enqueue_task<'a>(
        &'a self,
        kind: &'a str,
        params: &'a serde_json::Value,
        actor_id: Option<Uuid>,
        priority: i16,
        trigger_source: &'a str,
        idempotency_key: Option<&'a IdempotencyKey>,
    ) -> BoxFuture<'a, DomainResult<EnqueueOutcome>> {
        let _ = (
            kind,
            params,
            actor_id,
            priority,
            trigger_source,
            idempotency_key,
        );
        Box::pin(async { Err(DomainError::Invariant("not implemented".into())) })
    }

    /// Delete a `jobs` row by `id`. Used as a compensating action by
    /// `TaskUseCase::enqueue` when the event-store append fails after a
    /// successful insert (best-effort rollback — not a true two-phase
    /// commit). Returns `Ok(())` if the row was deleted or did not exist;
    /// returns an error only for unexpected infrastructure failures.
    ///
    /// **Rollback-only.** Do not call from any path other than
    /// compensating-delete sequences. This method deliberately does NOT
    /// audit its own delete; a production-facing delete path must emit
    /// its own domain event first.
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("not implemented"))`.
    fn delete_job<'a>(&'a self, job_id: Uuid) -> BoxFuture<'a, DomainResult<()>> {
        let _ = job_id;
        Box::pin(async { Err(DomainError::Invariant("not implemented".into())) })
    }

    /// List jobs with optional filtering and cursor-based pagination.
    ///
    /// Results are ordered by `id DESC` (most-recently-inserted first).
    /// When `cursor` is `Some(id)`, only rows whose `id < cursor` are
    /// returned (exclusive lower bound). `limit` is clamped to the
    /// adapter's maximum page size; a value of `0` selects the default.
    ///
    /// Used by `GET /api/v1/admin/tasks`.
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("not implemented"))` so test fixtures
    /// that do not need the list path compile without modification.
    fn list_jobs<'a>(
        &'a self,
        filter: ListJobsFilter,
        limit: u32,
        cursor: Option<Uuid>,
    ) -> BoxFuture<'a, DomainResult<ListJobsPage>> {
        let _ = (filter, limit, cursor);
        Box::pin(async { Err(DomainError::Invariant("list_jobs not implemented".into())) })
    }

    /// Fetch a single jobs row by id. Returns `Ok(None)` when the row
    /// does not exist (including when it has never been inserted).
    ///
    /// Used by `GET /api/v1/admin/tasks/:id`.
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("not implemented"))`.
    fn get_job<'a>(&'a self, job_id: Uuid) -> BoxFuture<'a, DomainResult<Option<JobRow>>> {
        let _ = job_id;
        Box::pin(async { Err(DomainError::Invariant("get_job not implemented".into())) })
    }

    /// Return the newest
    /// `completed_at` for a row with `kind = $1 AND status = 'completed'`,
    /// or `Ok(None)` when no such completed row exists.
    ///
    /// Powers the boot-time staging-sweep liveness signal: a deployment
    /// that upgraded without enabling the `staging-sweep` CronJob (the
    /// `cronJobs.enabled:false` default) or runs non-k8s gets no sweep
    /// at all, accumulates orphaned staging entries unbounded, and
    /// nothing alerts. The composition root calls this once at boot
    /// with `kind = "staging-sweep"`, feeds the result through the pure
    /// `hort_domain::policy::evaluate_staging_sweep_liveness` predicate,
    /// and emits `hort_staging_sweep_overdue` + a `warn!`.
    ///
    /// This is an **additive** read — it does not change any existing
    /// method signature. Ordering is `completed_at DESC` (NOT `id DESC`:
    /// `jobs.id` is `gen_random_uuid()`, so id order is not time order).
    ///
    /// **Default implementation:** returns `Ok(None)` so existing test
    /// fixtures and mocks that pre-date this method compile without
    /// modification (same additive-default pattern as
    /// [`Self::find_active_scan_for_artifact`]). A `None` result is the
    /// "never ran" case the predicate already handles as overdue, so a
    /// mock that does not override this is fail-safe (signals overdue),
    /// not fail-silent.
    fn last_completed_at_by_kind<'a>(
        &'a self,
        kind: &'a str,
    ) -> BoxFuture<'a, DomainResult<Option<DateTime<Utc>>>> {
        let _ = kind;
        Box::pin(async { Ok(None) })
    }

    /// Return the `result_summary` of the most-recently-completed
    /// (`completed_at DESC`) row with `kind = $1 AND status =
    /// 'completed'`, or `Ok(None)` when no such row exists.
    ///
    /// A recurring, single-active task kind (e.g. `prefetch-tick`) gets
    /// a brand-new `jobs` row on every scheduled invocation (there is
    /// no in-place row reuse), so cross-tick state cannot live on
    /// `params`, which is fixed at enqueue time. `result_summary`,
    /// however, is exactly the durable state each tick already writes
    /// on completion — this method is how the NEXT tick's fresh row
    /// reads the PREVIOUS row's summary back to resume a rotation
    /// (e.g. a keyset walk cursor) without a dedicated table or a
    /// column on the entity being walked. Mirrors
    /// [`Self::last_completed_at_by_kind`]'s read-only,
    /// `completed_at`-ordered shape.
    ///
    /// **Default implementation:** returns `Ok(None)` so existing
    /// mocks compile without modification — a handler reading `None`
    /// degrades to "start from the beginning," which is correct for a
    /// kind that has never completed. The Postgres adapter overrides
    /// with the real query.
    fn last_result_summary_by_kind<'a>(
        &'a self,
        kind: &'a str,
    ) -> BoxFuture<'a, DomainResult<Option<serde_json::Value>>> {
        let _ = kind;
        Box::pin(async { Ok(None) })
    }

    /// Record that a recurring,
    /// non-worker-dispatched run (e.g. the `verify-event-chain` CLI
    /// invoked by its CronJob) completed at `at`. Inserts a single
    /// terminal `jobs` row with `status='completed'`, `kind=<arg>`, and
    /// `completed_at=at`, so the boot-time liveness signal can later read
    /// the newest completion via [`Self::last_completed_at_by_kind`].
    ///
    /// This is the producer half of the `hort_event_chain_verify_overdue`
    /// gauge: the verify CLI already connects to the DB to read the event
    /// chain, so it records its own heartbeat here rather than going
    /// through the worker `jobs` claim/dispatch lifecycle (the verify run
    /// is a direct `hort-server` subcommand, not a worker `TaskHandler`).
    ///
    /// **Additive, observability-only.** A recording failure must NOT
    /// block the run's verdict — the caller logs and continues (mirroring
    /// the staging-sweep "observability not fail-closed" posture). The
    /// row is purely a liveness breadcrumb; it carries no `params`,
    /// `actor_id`, or scan-typed columns.
    ///
    /// **Default implementation:** returns `Ok(())` so existing mock
    /// `JobsRepository` impls (the `hort-app` use-case test_support mocks
    /// and the `MockJobsRepository` fixtures) keep compiling without
    /// modification. The Postgres adapter overrides this with the real
    /// INSERT.
    fn record_run_completion<'a>(
        &'a self,
        kind: &'a str,
        at: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<()>> {
        let _ = (kind, at);
        Box::pin(async { Ok(()) })
    }

    /// Claim up to `batch_size` pending rows whose `kind` is in `kinds`,
    /// transitioning them from `pending` → `running` atomically via
    /// `FOR UPDATE SKIP LOCKED`. Returns the post-update rows as
    /// [`JobRow`] (generic cross-kind projection).
    ///
    /// Used by [`TaskDispatcher`](crate::ports::task_handler)
    /// to claim across all registered handler kinds in one query.
    ///
    /// `worker_id` becomes `locked_by`. `lock_duration` is the lease window —
    /// a worker that dies mid-task lets the lock expire so another worker can
    /// re-claim the row.
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("not implemented"))` so existing test
    /// fixtures that pre-date this method continue to compile without
    /// modification. Tests and adapters that exercise the dispatcher override
    /// this method.
    fn claim_pending_by_kinds<'a>(
        &'a self,
        kinds: &'a [&'a str],
        batch_size: u16,
        worker_id: &'a str,
        lock_duration: Duration,
    ) -> BoxFuture<'a, DomainResult<Vec<JobRow>>> {
        let _ = (kinds, batch_size, worker_id, lock_duration);
        Box::pin(async {
            Err(DomainError::Invariant(
                "claim_pending_by_kinds not implemented".into(),
            ))
        })
    }

    /// Group the **claim-eligible pending** rows of the `jobs` table by
    /// `kind`, returning per-kind count + oldest `created_at`.
    ///
    /// Deliberately NOT filtered by the caller's registered kinds: this
    /// is the input to the dispatcher's starvation audit, whose blind
    /// spot is precisely a kind the poll loop does not claim. A kind with
    /// eligible rows that the dispatcher never claims — because no
    /// handler is registered for it, or because it loses the
    /// `priority DESC, created_at ASC` race on every poll — is otherwise
    /// invisible: the claim query filters it out and every log stays
    /// silent.
    ///
    /// **Default implementation:** returns `Ok(Vec::new())` (no backlog
    /// observed) so existing mock `JobsRepository` impls keep compiling
    /// and the audit is inert for them. The Postgres adapter overrides it
    /// with the real grouped aggregate.
    fn eligible_pending_by_kind(&self) -> BoxFuture<'_, DomainResult<Vec<PendingKindBacklog>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    /// Batch-insert prefetch cascade jobs with
    /// L3-dedup absorption.
    ///
    /// The transitive prefetch cascade
    /// (`PrefetchDependenciesHandler`) calls this once per resolved
    /// dependency cohort. Each row's `target_key` is the canonical
    /// `"{repo_id}|{format}|{normalised_package}|{version}"` key
    /// described on the `jobs.target_key` column (migration 009).
    /// The Postgres adapter runs a single multi-row
    ///
    /// ```sql
    /// INSERT INTO public.jobs (kind, params, priority, trigger_source, target_key, status)
    ///     VALUES ($1,$2,…), ($n+1,$n+2,…), …
    ///     ON CONFLICT (target_key)
    ///     WHERE kind = 'prefetch' AND target_key IS NOT NULL AND status IN ('pending','running')
    ///     DO NOTHING
    /// RETURNING id
    /// ```
    ///
    /// (one statement per `kind` value present in the batch — both
    /// `'prefetch'` and `'prefetch-dependencies'` kinds use this entry
    /// point, and the adapter dispatches to the matching partial
    /// unique index). The returned `Vec<Uuid>` contains one `id` per
    /// row that actually inserted; rows absorbed by the partial
    /// unique index do NOT appear in the result (the cascade reads
    /// the length to count "new enqueues for this walk"; the planner
    /// emits dedup metrics from `batch.len() - returned.len()`).
    ///
    /// The dedup IS the insert — no read-then-insert race window
    /// between the planner reading "is `(repo, package, version)`
    /// already enqueued?" and the writer inserting it.
    ///
    /// **Why a separate entry point from [`Self::enqueue_task`].**
    /// `enqueue_task` is a single-row INSERT without `ON CONFLICT`;
    /// using it for the cascade would either (a) require N round-trips
    /// per cohort (latency + lock churn) or (b) silently surface the
    /// partial-unique-index violations as `Err(Conflict)` per duplicate,
    /// each of which the planner would have to swallow individually.
    /// The batch+ON-CONFLICT contract bundles both wins into one
    /// statement.
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("enqueue_prefetch_batch not implemented"))`
    /// so existing test fixtures that pre-date this method continue to
    /// compile without modification.
    fn enqueue_prefetch_batch<'a>(
        &'a self,
        rows: &'a [PrefetchEnqueueRow],
    ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>> {
        let _ = rows;
        Box::pin(async {
            Err(DomainError::Invariant(
                "enqueue_prefetch_batch not implemented".into(),
            ))
        })
    }

    /// Batch-insert jobs deduped by `idempotency_key`, absorbing
    /// collisions in the index rather than surfacing them per row.
    ///
    /// The sibling of [`Self::enqueue_prefetch_batch`] for every cohort
    /// whose dedup key is the **unscoped** `jobs_idempotency_key_uq`
    /// index (`WHERE idempotency_key IS NOT NULL`, migration 009) rather
    /// than the `prefetch%`-scoped `target_key` one. The two are not
    /// interchangeable: `enqueue_prefetch_batch`'s `ON CONFLICT` names an
    /// index that does not cover a non-`prefetch%` kind at all, so a
    /// caller outside the cascade needs this entry point.
    ///
    /// The Postgres adapter runs a single multi-row
    ///
    /// ```sql
    /// INSERT INTO public.jobs
    ///     (kind, params, priority, trigger_source, idempotency_key, status)
    ///     VALUES ($1,$2,…), ($n+1,$n+2,…), …
    ///     ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL
    ///     DO NOTHING
    /// RETURNING id
    /// ```
    ///
    /// The returned `Vec<Uuid>` holds one id per row that actually
    /// inserted; rows the unique index absorbed do NOT appear, so a
    /// caller counts dedup hits as `rows.len() - returned.len()`. Unlike
    /// [`Self::enqueue_task`] there is no per-row
    /// [`EnqueueOutcome::Duplicate`] and no existing-row id — a cohort
    /// caller wants the counts, and recovering N existing ids would cost
    /// the round-trip this entry point exists to remove. Two rows in the
    /// same call carrying the same key collapse to one insert as well:
    /// `DO NOTHING` resolves intra-statement conflicts the same way it
    /// resolves conflicts with already-committed rows.
    ///
    /// **Why a separate entry point from [`Self::enqueue_task`]** — the
    /// same argument [`Self::enqueue_prefetch_batch`] records, applied to
    /// this index. `enqueue_task` is a single-row statement, so a cohort
    /// of N means either N round-trips of latency and lock churn, or N
    /// conflicts surfaced and swallowed one at a time. The
    /// batch+ON-CONFLICT contract bundles both wins into one statement,
    /// which matters most on the request path: the OCI eager index-child
    /// enqueue runs inside a live pull-through's coalescing window, where
    /// every extra round-trip is latency other clients pulling the same
    /// index also wait behind.
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("enqueue_idempotent_batch not implemented"))`
    /// so existing test fixtures that pre-date this method continue to
    /// compile without modification.
    fn enqueue_idempotent_batch<'a>(
        &'a self,
        rows: &'a [IdempotentEnqueueRow],
    ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>> {
        let _ = rows;
        Box::pin(async {
            Err(DomainError::Invariant(
                "enqueue_idempotent_batch not implemented".into(),
            ))
        })
    }

    /// Retention sweep for the pull-through ingest cascade — delete
    /// terminal `kind LIKE 'prefetch%'` (minus `prefetch-tick`) and
    /// `kind = 'oci-index-child-ingest'` rows whose `updated_at < now() -
    /// $horizon`. Returns the number of rows deleted.
    ///
    /// The cascade is high-churn (a closure-warm enqueues thousands
    /// of rows); without periodic GC the `jobs` table grows
    /// unbounded. The sweep targets:
    ///
    /// ```sql
    /// DELETE FROM public.jobs
    ///  WHERE ((kind LIKE 'prefetch%' AND kind <> 'prefetch-tick')
    ///         OR kind = 'oci-index-child-ingest')
    ///    AND status IN ('completed', 'failed')
    ///    AND updated_at < now() - $1::interval
    /// ```
    ///
    /// **Why `prefetch-tick` is carved out.** This sweep has no
    /// keep-newest clause, because its premise is that none of the rows
    /// it reaches hold durable state. `prefetch-tick` breaks that
    /// premise: it matches the `prefetch%` prefix by name only — it is a
    /// scheduled tick, not cascade work — and the rotation's keyset
    /// cursor lives in the `result_summary` of its newest `completed`
    /// row, read back through [`Self::last_result_summary_by_kind`]. An
    /// instance whose `prefetch-tick` schedule was off or failing for
    /// longer than the horizon would lose the cursor here and restart the
    /// rotation from the beginning, so on a large instance the tail
    /// packages would come up rarely or never. The kind is swept by
    /// [`Self::delete_terminal_other_kind_rows_older_than`] instead,
    /// which retains the newest `completed` row per kind. The carve-out
    /// and that sweep's matching `OR kind = 'prefetch-tick'` admission
    /// are mirror images: break one and the kind is either swept twice or
    /// never swept.
    ///
    /// **Why `oci-index-child-ingest` rides this sweep and not its own.**
    /// It is the same class of work as the cascade: high-churn (one row
    /// per declared child manifest per repository, and an index declares
    /// many), best-effort, and holding nothing durable in its terminal
    /// row. Deleting one is safe because **the jobs row is the second
    /// dedupe layer, not the only one**: `jobs.idempotency_key` suppresses
    /// a re-enqueue only while the row exists, but the handler's
    /// target-repository presence check suppresses the *work*
    /// permanently. A swept row that is later re-enqueued short-circuits
    /// on that check before it touches the network — a cheap no-op, never
    /// a re-fetch and never a re-anchor. Every other `jobs.kind` outside
    /// these two keeps its newest terminal row as durable state (e.g.
    /// `verify-event-chain`'s liveness breadcrumb), which is why widening
    /// the predicate further is not a free change — `prefetch-tick` is
    /// the worked example of exactly that cost.
    ///
    /// `pending`/`running` rows are deliberately excluded — they are
    /// either claim-pending (the worker has not picked them up yet)
    /// or in flight (the worker is processing them); deleting either
    /// would tank the in-flight work.
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("delete_terminal_prefetch_rows_older_than not implemented"))`
    /// so existing test fixtures compile without modification.
    fn delete_terminal_prefetch_rows_older_than<'a>(
        &'a self,
        horizon: Duration,
    ) -> BoxFuture<'a, DomainResult<u64>> {
        let _ = horizon;
        Box::pin(async {
            Err(DomainError::Invariant(
                "delete_terminal_prefetch_rows_older_than not implemented".into(),
            ))
        })
    }

    /// Retention sweep for `kind='scan'` rows — delete terminal
    /// (`status IN ('completed', 'failed')`) scan rows whose
    /// `updated_at < now() - $horizon`. Returns the number of rows
    /// deleted.
    ///
    /// ```sql
    /// DELETE FROM public.jobs
    ///  WHERE kind = 'scan'
    ///    AND status IN ('completed', 'failed')
    ///    AND updated_at < now() - $1::interval
    /// ```
    ///
    /// **`kind = 'scan'` exactly** — every other `jobs.kind` keeps its
    /// newest terminal row as durable state (e.g. `verify-event-chain`'s
    /// liveness breadcrumb; the transitive-cascade rows have their own
    /// sweep in [`Self::delete_terminal_prefetch_rows_older_than`]).
    /// Widening the `WHERE kind = 'scan'` predicate would delete another
    /// kind's durable state out from under it.
    ///
    /// `pending`/`running` rows are deliberately excluded — they are
    /// either claim-pending or in flight; deleting either would tank
    /// in-progress scan work. Every successful and every permanently-
    /// failed scan leaves a terminal row forever without this sweep —
    /// a periodic rescan cadence or a scanner outage (stranded-requeue
    /// exhaustion) both accumulate rows unbounded.
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("delete_terminal_scan_rows_older_than not implemented"))`
    /// so existing test fixtures compile without modification.
    fn delete_terminal_scan_rows_older_than<'a>(
        &'a self,
        horizon: Duration,
    ) -> BoxFuture<'a, DomainResult<u64>> {
        let _ = horizon;
        Box::pin(async {
            Err(DomainError::Invariant(
                "delete_terminal_scan_rows_older_than not implemented".into(),
            ))
        })
    }

    /// Retention sweep for **every kind the two kind-specific sweeps
    /// above do not reach** — delete terminal
    /// (`status IN ('completed', 'failed')`) rows whose
    /// `updated_at < now() - $horizon`, **except** the rows the
    /// jobs-row-as-state readers depend on. Returns the number of rows
    /// deleted.
    ///
    /// ```sql
    /// WITH live AS (
    ///     SELECT kind,
    ///            max(completed_at) FILTER (WHERE status = 'completed')
    ///              AS newest_completed_at,
    ///            max(created_at) AS newest_created_at
    ///       FROM public.jobs
    ///      WHERE status IN ('completed', 'failed')
    ///        AND (kind NOT LIKE 'prefetch%' OR kind = 'prefetch-tick')
    ///        AND kind NOT IN ('scan', 'oci-index-child-ingest')
    ///      GROUP BY kind
    /// )
    /// DELETE FROM public.jobs j
    ///  USING live l
    ///  WHERE l.kind = j.kind
    ///    AND j.status IN ('completed', 'failed')
    ///    AND j.updated_at < now() - $1::interval
    ///    AND NOT (j.status = 'completed'
    ///             AND j.completed_at IS NOT DISTINCT FROM l.newest_completed_at)
    ///    AND j.created_at <> l.newest_created_at
    /// ```
    ///
    /// **Why the kind exclusions.** `kind = 'scan'` and the cascade
    /// predicate already have sweeps of their own, each carrying its own
    /// horizon constant. A second sweep covering the same rows would let
    /// the shorter of the two constants silently win, so a kind covered
    /// twice would age out on a horizon neither of its sweeps documents.
    /// All three constants read 7 days today, which makes such an overlap
    /// invisible rather than harmless — it would surface the first time
    /// one of them moved. The exclusions are therefore expressed as the
    /// complement of the two sibling predicates — textually, not as a
    /// list of kinds — so the one-sweep-per-kind property holds by
    /// construction and a new `prefetch%` kind inherits the cascade sweep
    /// without a matching edit here.
    ///
    /// **Why `prefetch-tick` is readmitted.** It is the single exception
    /// to the textual complement, and it is written as one: the cascade
    /// sweep carves the kind out, and `OR kind = 'prefetch-tick'` takes
    /// it back here. That kind's newest `completed` row carries the
    /// prefetch rotation's keyset cursor, and this is the sweep with the
    /// keep-newest clause that protects it. See
    /// [`Self::delete_terminal_prefetch_rows_older_than`] for the full
    /// argument.
    ///
    /// **Why two rows per kind can survive the horizon.** "Keep the
    /// newest terminal row" is not sufficient: the two liveness gauges
    /// read [`Self::last_completed_at_by_kind`] and the prefetch rotation
    /// reads [`Self::last_result_summary_by_kind`], and **both filter
    /// `status = 'completed'`**. A kind whose newest terminal row is a
    /// `failed` one (a sweep that ran, then started failing) would keep
    /// that `failed` row and lose the older `completed` row underneath
    /// it — so `last_completed_at_by_kind` would answer `None`, i.e.
    /// "never ran", for a task that demonstrably ran. The two retained
    /// rows are therefore:
    ///
    /// - the newest `completed` row per kind, matching
    ///   `max(completed_at)` / `ORDER BY completed_at DESC LIMIT 1`
    ///   exactly, so the row kept is the row those readers read;
    /// - the newest terminal row per kind by `created_at`, matching the
    ///   `ORDER BY created_at DESC LIMIT 1` shape a
    ///   latest-job-decides-the-predicate reader uses (the artifact
    ///   rescan-stranding probe is the live example of that shape).
    ///
    /// Equality rather than a ranking window is deliberate: on a
    /// `completed_at` tie the readers pick arbitrarily between the tied
    /// rows, so the sweep keeps all of them rather than guessing which
    /// one the reader would land on. `IS NOT DISTINCT FROM` on
    /// `completed_at` makes a `completed` row with a NULL `completed_at`
    /// (only reachable by a writer that bypasses this port) retained
    /// rather than deleted, which is also what `ORDER BY completed_at
    /// DESC` would read first.
    ///
    /// `pending`/`running` rows are excluded for the same reason as in
    /// the two sibling sweeps — they are claim-pending or in flight.
    /// Note that this leaves a row abandoned in `running` by a crashed
    /// worker untouched: an expired lease does not distinguish a dead
    /// worker from a task that is simply slower than its lease, and no
    /// lease-renewal exists to make that distinction. Reaping those is a
    /// requeue problem, not a retention problem.
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("delete_terminal_other_kind_rows_older_than not implemented"))`
    /// so existing test fixtures compile without modification.
    fn delete_terminal_other_kind_rows_older_than<'a>(
        &'a self,
        horizon: Duration,
    ) -> BoxFuture<'a, DomainResult<u64>> {
        let _ = horizon;
        Box::pin(async {
            Err(DomainError::Invariant(
                "delete_terminal_other_kind_rows_older_than not implemented".into(),
            ))
        })
    }
}

/// One row to insert via
/// [`JobsRepository::enqueue_prefetch_batch`]. Bundles the per-row
/// columns into a single struct so the trait signature stays
/// stable as new fields are added (the cascade is the only consumer
/// — adding e.g. `actor_id` would otherwise widen every caller's
/// argument list).
///
/// `target_key` is the L3 dedup key, populated by
/// [`PrefetchTargetKey::canonical`].
#[derive(Debug, Clone, PartialEq)]
pub struct PrefetchEnqueueRow {
    /// One of `"prefetch"` or `"prefetch-dependencies"`. Other kinds
    /// must use [`JobsRepository::enqueue_task`] instead (the L3
    /// partial unique index is `prefetch%`-scoped — a
    /// non-`prefetch%` kind has no index to dedup against).
    pub kind: String,
    /// JSONB row params — the per-kind handler shape. For
    /// `prefetch` rows: `{"repository_id":…,"package":…,"version":…}`.
    /// For `prefetch-dependencies` rows: `{"artifact_id":…,"current_depth":…}`.
    pub params: serde_json::Value,
    /// Priority ranking (see [`TriggerSource`]). Cascade rows carry priority 0
    /// (the schema default) so manual / cron / advisory drain first.
    pub priority: i16,
    /// One of the `trigger_source` CHECK literals (migration 009).
    /// Cascade-spawned rows carry `"prefetch"` to distinguish from
    /// cron / advisory / ingest / manual / seed-import.
    pub trigger_source: String,
    /// L3 dedup key. Canonical shape:
    /// `"{repo_id}|{format}|{normalised_package}|{version}"`
    /// (the migration-009 `target_key` column comment is the
    /// source of truth on canonicalisation).
    pub target_key: String,
}

/// One row to insert via [`JobsRepository::enqueue_idempotent_batch`].
///
/// The `idempotency_key` sibling of [`PrefetchEnqueueRow`]: same
/// bundling rationale (the trait signature stays stable as columns are
/// added), different dedup index.
///
/// There is deliberately no `actor_id`. Every cohort reaching this entry
/// point is system-minted — a fan-out derived from content the server
/// just ingested, not an operator action — so the column would be `NULL`
/// on every row. A kind that needs operator attribution enqueues one row
/// at a time through [`JobsRepository::enqueue_task`], which carries it.
#[derive(Debug, Clone, PartialEq)]
pub struct IdempotentEnqueueRow {
    /// A `jobs.kind` CHECK literal (migration 009 and its successors).
    pub kind: String,
    /// JSONB row params — the per-kind handler shape.
    pub params: serde_json::Value,
    /// Priority ranking (see [`TriggerSource`]).
    pub priority: i16,
    /// One of the `trigger_source` CHECK literals (migration 009).
    pub trigger_source: String,
    /// Dedup key on the unscoped `jobs_idempotency_key_uq` partial
    /// unique index. Non-optional: a row with no key has nothing to
    /// dedup against and belongs on [`JobsRepository::enqueue_task`].
    pub idempotency_key: IdempotencyKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `JobsRepository` implementing **only** the trait's required
    /// methods, so every provided method it answers with is the trait's
    /// own default.
    ///
    /// This is the fixture behind every `*_default_impl_*` test below:
    /// each one pins what a mock that pre-dates a provided method does
    /// when that method is called, which is only meaningful against an
    /// impl that overrides nothing. Adding an override here would make
    /// all of those tests assert the override instead of the default —
    /// so a new provided method gets a new test, never a method on
    /// `Bare`.
    struct Bare;

    impl JobsRepository for Bare {
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
    }

    /// The shared fixture answers every REQUIRED method inertly. The
    /// `*_default_impl_*` tests below read a provided method's answer as
    /// the trait's default; that reading only holds if nothing the
    /// fixture does can influence it, which is what "inert" means here.
    #[tokio::test]
    async fn the_bare_fixture_answers_every_required_method_inertly() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        assert!(repo
            .claim_scan_jobs("w", 1, Duration::from_secs(1))
            .await
            .expect("claim_scan_jobs")
            .is_empty());
        repo.mark_completed(Uuid::nil(), serde_json::json!({}))
            .await
            .expect("mark_completed");
        repo.reschedule(Uuid::nil(), Duration::from_secs(1), "e")
            .await
            .expect("reschedule");
        repo.mark_failed(Uuid::nil(), "e")
            .await
            .expect("mark_failed");
        let hash: ContentHash = format!("{:064x}", 1).parse().expect("64-hex sha");
        assert_eq!(
            repo.enqueue_scan(Uuid::nil(), Uuid::nil(), &hash, "oci", 0, "manual")
                .await
                .expect("enqueue_scan"),
            Uuid::nil(),
        );
        assert!(
            repo.renew_lease(Uuid::nil(), "w", Duration::from_secs(1))
                .await
                .expect("renew_lease"),
            "the default renewal answers 'still yours' — a fixture has no lease to lose"
        );
        assert!(repo
            .requeue_abandoned(&["scan"], Duration::from_secs(1), 5, 10)
            .await
            .expect("requeue_abandoned")
            .is_empty());
    }

    /// Compile-time assertion that `JobsRepository` is dyn-compatible.
    #[test]
    fn jobs_repository_is_dyn_compatible() {
        let _ = size_of::<&dyn JobsRepository>();
    }

    /// `Box<dyn JobsRepository>` resolves — proves the trait can be
    /// type-erased into an owned trait object the way adapter
    /// composition roots will store it.
    #[test]
    fn jobs_repository_can_be_boxed() {
        let _: Option<Box<dyn JobsRepository>> = None;
    }

    /// `JobStatus::as_str` returns the exact SQL CHECK literal for each
    /// variant. Regression guard — drift from the migration's CHECK
    /// constraint would silently break adapter-side filtering.
    #[test]
    fn job_status_as_str_matches_sql_literals() {
        assert_eq!(JobStatus::Pending.as_str(), "pending");
        assert_eq!(JobStatus::Running.as_str(), "running");
        assert_eq!(JobStatus::Completed.as_str(), "completed");
        assert_eq!(JobStatus::Failed.as_str(), "failed");
    }

    /// `JobsRepository::pending_scan_count` is exposed on the trait and
    /// the default implementation returns `Ok(0)`. The Postgres adapter
    /// overrides this with the real `SELECT count(*)` query — the
    /// default exists so the legacy `MockJobsRepository` in
    /// `hort-app::use_cases::scan_orchestration_tests` (which predates
    /// this method) continues to compile without modification. This
    /// test pins the default-impl contract against accidental drift.
    #[tokio::test]
    async fn pending_scan_count_default_impl_returns_zero() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let depth = repo
            .pending_scan_count()
            .await
            .expect("default impl returns Ok");
        assert_eq!(depth, 0);
    }

    /// A custom `pending_scan_count` override is reachable through the
    /// trait object — pins the dispatch shape the worker's heartbeat
    /// loop relies on once the Postgres adapter overrides the default.
    #[tokio::test]
    async fn pending_scan_count_override_dispatches_through_trait_object() {
        struct WithOverride(i64);
        impl JobsRepository for WithOverride {
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
            fn pending_scan_count<'a>(&'a self) -> BoxFuture<'a, DomainResult<i64>> {
                let v = self.0;
                Box::pin(async move { Ok(v) })
            }
        }

        let repo: Box<dyn JobsRepository> = Box::new(WithOverride(7));
        let depth = repo
            .pending_scan_count()
            .await
            .expect("override returns Ok");
        assert_eq!(depth, 7);
    }

    /// `JobsRepository::enqueue_task` default impl returns `Err(Invariant)`
    /// with the "not implemented" message — pins the same contract as
    /// `pending_scan_count`'s default, ensuring existing test mocks that
    /// don't override `enqueue_task` fail loudly rather than silently
    /// returning wrong data.
    #[tokio::test]
    async fn enqueue_task_default_impl_returns_invariant_error() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let params = serde_json::json!({});
        let err = repo
            .enqueue_task("noop", &params, None, 0, "test", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant error, got {err:?}"
        );
    }

    /// Pins the default impl shape against the
    /// 6-arg signature when an `idempotency_key` is supplied. A mock
    /// that pre-dates the idempotency-key arg still fails loudly (same
    /// `Invariant` error) regardless of whether the caller passes
    /// `None` or `Some` — the default ignores the new arg.
    #[tokio::test]
    async fn enqueue_task_default_impl_returns_invariant_error_with_idempotency_key() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let params = serde_json::json!({});
        let key = IdempotencyKey::try_from("cron:retention-purge:2026-06-03").expect("valid key");
        let err = repo
            .enqueue_task("noop", &params, None, 0, "test", Some(&key))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant error, got {err:?}"
        );
    }

    /// `EnqueueOutcome` derives `Clone + PartialEq + Eq` so mocks can
    /// equate observed outcomes against expectations.
    #[test]
    fn enqueue_outcome_clone_and_eq() {
        let id = Uuid::new_v4();
        let enq = EnqueueOutcome::Enqueued { job_id: id };
        let dup = EnqueueOutcome::Duplicate {
            existing_job_id: id,
        };
        assert_eq!(enq.clone(), enq);
        assert_eq!(dup.clone(), dup);
        assert_ne!(enq, dup);
    }

    /// `JobsRepository::delete_job` default impl returns `Err(Invariant)`.
    #[tokio::test]
    async fn delete_job_default_impl_returns_invariant_error() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let err = repo.delete_job(Uuid::nil()).await.unwrap_err();
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant error, got {err:?}"
        );
    }

    /// `ScanJob` is `Clone + PartialEq` so test fixtures can be cloned
    /// across mock interactions and assertions can use `assert_eq!`.
    #[test]
    fn scan_job_is_clone_and_partial_eq() {
        let id = Uuid::nil();
        let artifact_id = Uuid::nil();
        let repository_id = Uuid::nil();
        let content_hash: ContentHash =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap();
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let job = ScanJob {
            id,
            artifact_id,
            repository_id,
            content_hash,
            format: "npm".into(),
            status: JobStatus::Pending,
            attempts: 0,
            locked_by: None,
            locked_until: None,
            last_error: None,
            created_at: now,
            updated_at: now,
            trigger_source: TriggerSource::Ingest,
            priority: 0,
        };
        let cloned = job.clone();
        assert_eq!(job, cloned);
    }

    /// Regression guard — `ScanJob` carries `trigger_source` and
    /// `priority`. A cron-enqueued row with `priority=10` round-trips
    /// through the struct and Clone preserves both fields.
    #[test]
    fn scan_job_carries_trigger_source_and_priority() {
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let job = ScanJob {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            content_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap(),
            format: "npm".into(),
            status: JobStatus::Pending,
            attempts: 0,
            locked_by: None,
            locked_until: None,
            last_error: None,
            created_at: now,
            updated_at: now,
            trigger_source: TriggerSource::Cron,
            priority: 10,
        };
        assert_eq!(job.trigger_source, TriggerSource::Cron);
        assert_eq!(job.priority, 10);
        let cloned = job.clone();
        assert_eq!(cloned.trigger_source, TriggerSource::Cron);
        assert_eq!(cloned.priority, 10);
    }

    // ---- TriggerSource enum -------------------------------------------------

    /// `TriggerSource::as_str` returns the exact SQL CHECK literal for
    /// each variant. Drift here would silently break adapter-side
    /// `WHERE trigger_source = $1` filters and let mis-categorised
    /// observability emissions through.
    #[test]
    fn trigger_source_as_str_matches_sql_literals() {
        assert_eq!(TriggerSource::Ingest.as_str(), "ingest");
        assert_eq!(TriggerSource::Cron.as_str(), "cron");
        assert_eq!(TriggerSource::Advisory.as_str(), "advisory");
        assert_eq!(TriggerSource::Manual.as_str(), "manual");
    }

    /// `Display` matches `as_str` for every variant — used by `tracing`
    /// fields and metric labels.
    #[test]
    fn trigger_source_display_matches_as_str() {
        for v in [
            TriggerSource::Ingest,
            TriggerSource::Cron,
            TriggerSource::Advisory,
            TriggerSource::Manual,
        ] {
            assert_eq!(format!("{v}"), v.as_str());
        }
    }

    /// `FromStr` round-trips every documented literal back to its
    /// variant. The `Display`/`FromStr` pair is the contract the
    /// adapter row-mapper depends on.
    #[test]
    fn trigger_source_from_str_round_trips_each_variant() {
        for v in [
            TriggerSource::Ingest,
            TriggerSource::Cron,
            TriggerSource::Advisory,
            TriggerSource::Manual,
        ] {
            let parsed: TriggerSource = v.as_str().parse().expect("each variant parses");
            assert_eq!(parsed, v);
        }
    }

    /// **Critical guard.** `from_str("advisory_watch")` must NOT silently
    /// resolve to `TriggerSource::Advisory`. The watch tick handler's
    /// kind is `"advisory-watch-tick"` but its `trigger_source` column
    /// is `"advisory"` — a future code path that mistakenly passes the
    /// underscored / hyphenated form would either fail the SQL CHECK at
    /// INSERT (loud) or, if the CHECK were ever loosened, end up filed
    /// under the wrong observability bucket (silent). This test pins
    /// the strict-rejection contract so the silent-mis-categorisation
    /// path stays closed at the parse boundary.
    #[test]
    fn trigger_source_from_str_rejects_underscore_advisory_watch() {
        let err = TriggerSource::from_str("advisory_watch")
            .expect_err("'advisory_watch' must NOT parse — the SQL CHECK literal is 'advisory'");
        assert!(
            matches!(err, DomainError::Validation(_)),
            "expected Validation error, got {err:?}"
        );
    }

    /// Other unknown literals also produce `Validation`. Pins the
    /// happy-path-vs-sad-path discriminator the adapter relies on.
    #[test]
    fn trigger_source_from_str_rejects_unknown_literal() {
        for bad in ["", "INGEST", " cron", "scheduled", "operator"] {
            let err = TriggerSource::from_str(bad)
                .unwrap_err_or_else_panic("expected unknown literal to fail");
            assert!(
                matches!(err, DomainError::Validation(_)),
                "expected Validation for {bad:?}, got {err:?}"
            );
        }
    }

    /// Helper trait for ergonomic `Result::unwrap_err` with a panic
    /// message — keeps the assertion above readable when iterating over
    /// inputs.
    trait UnwrapErrOrElsePanic<T, E> {
        fn unwrap_err_or_else_panic(self, msg: &str) -> E;
    }
    impl<T: fmt::Debug, E> UnwrapErrOrElsePanic<T, E> for Result<T, E> {
        fn unwrap_err_or_else_panic(self, msg: &str) -> E {
            match self {
                Ok(v) => panic!("{msg}: got Ok({v:?})"),
                Err(e) => e,
            }
        }
    }

    /// `serde` round-trips through the `lowercase` rename — the column
    /// literal is also the JSON literal, so `params` JSONB blobs that
    /// embed a `trigger_source` field stay coherent with the column.
    #[test]
    fn trigger_source_serde_round_trips_lowercase() {
        let json = serde_json::to_string(&TriggerSource::Advisory).expect("serialize");
        assert_eq!(json, "\"advisory\"");
        let back: TriggerSource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, TriggerSource::Advisory);
    }

    /// `ListJobsFilter::default()` produces an all-None filter
    /// (no kind/status restriction). Pins the derived-Default semantics.
    #[test]
    fn list_jobs_filter_default_is_all_none() {
        let f = ListJobsFilter::default();
        assert!(f.kind.is_none());
        assert!(f.status.is_none());
    }

    /// `JobsRepository::list_jobs` default impl returns `Err(Invariant)`
    /// — same contract as `get_job`. Existing mocks that pre-date the
    /// method compile without modification; tests that need the method
    /// override it.
    #[tokio::test]
    async fn list_jobs_default_impl_returns_invariant_error() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let err = repo
            .list_jobs(ListJobsFilter::default(), 10, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant for list_jobs default impl, got {err:?}"
        );
    }

    /// `JobsRepository::get_job` default impl returns `Err(Invariant)`.
    #[tokio::test]
    async fn get_job_default_impl_returns_invariant_error() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let err = repo.get_job(Uuid::nil()).await.unwrap_err();
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant for get_job default impl, got {err:?}"
        );
    }

    /// `JobRow` is `Clone` so handler tests can clone rows from mock
    /// responses without dropping them.
    #[test]
    fn job_row_is_clone() {
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let row = JobRow {
            id: Uuid::nil(),
            kind: "noop".into(),
            status: JobStatus::Pending,
            params: Some(serde_json::json!({})),
            actor_id: None,
            priority: 0,
            trigger_source: "manual".into(),
            attempts: 0,
            created_at: now,
            updated_at: now,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
        };
        let cloned = row.clone();
        assert_eq!(cloned.kind, "noop");
    }

    /// `JobsRepository::last_completed_at_by_kind` default impl returns
    /// `Ok(None)`. Unlike the
    /// `Err(Invariant)` defaults, this one is `Ok(None)` because `None`
    /// is the well-defined "never ran" input the liveness predicate
    /// already classifies as overdue — a non-overriding mock is
    /// fail-safe (signals overdue), never fail-silent.
    #[tokio::test]
    async fn last_completed_at_by_kind_default_impl_returns_none() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let out = repo
            .last_completed_at_by_kind("staging-sweep")
            .await
            .expect("default impl returns Ok");
        assert_eq!(out, None);
    }

    /// `JobsRepository::record_run_completion` default impl returns
    /// `Ok(())` — the additive method
    /// must not break existing mock impls that pre-date it. The Postgres
    /// adapter overrides this with the real INSERT; a non-overriding mock
    /// silently no-ops (observability-only, never fail-closed).
    #[tokio::test]
    async fn record_run_completion_default_impl_returns_ok() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        repo.record_run_completion("verify-event-chain", Utc::now())
            .await
            .expect("default impl returns Ok(())");
    }

    /// `JobsRepository::claim_pending_by_kinds` default impl returns
    /// `Err(Invariant)` — same pattern as the other deferred methods.
    /// Tests and adapters that exercise the dispatcher override this method.
    #[tokio::test]
    async fn claim_pending_by_kinds_default_impl_returns_invariant_error() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let err = repo
            .claim_pending_by_kinds(&["noop"], 10, "worker-test", Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant for claim_pending_by_kinds default impl, got {err:?}"
        );
    }

    // -- Prefetch-cascade-specific entry points -----------------------------

    /// `enqueue_prefetch_batch` default impl surfaces `Invariant` so a
    /// mock that pre-dates the method fails loudly instead of silently
    /// reporting "no rows inserted".
    #[tokio::test]
    async fn enqueue_prefetch_batch_default_impl_returns_invariant_error() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let rows = vec![PrefetchEnqueueRow {
            kind: "prefetch".to_string(),
            params: serde_json::json!({"x": 1}),
            priority: 0,
            trigger_source: "prefetch".to_string(),
            target_key: "key".to_string(),
        }];
        let err = repo.enqueue_prefetch_batch(&rows).await.unwrap_err();
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant for enqueue_prefetch_batch default impl, got {err:?}"
        );
    }

    /// `enqueue_idempotent_batch` default impl surfaces `Invariant` for
    /// the same reason its `target_key` sibling does: a mock that
    /// pre-dates the method must fail loudly rather than silently
    /// reporting "no rows inserted", which a caller counting
    /// `rows.len() - returned.len()` would read as "all deduped".
    #[tokio::test]
    async fn enqueue_idempotent_batch_default_impl_returns_invariant_error() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let rows = vec![IdempotentEnqueueRow {
            kind: "oci-index-child-ingest".to_string(),
            params: serde_json::json!({"x": 1}),
            priority: 0,
            trigger_source: "ingest".to_string(),
            idempotency_key: IdempotencyKey::try_from("some-key".to_string())
                .expect("valid idempotency key"),
        }];
        let err = repo.enqueue_idempotent_batch(&rows).await.unwrap_err();
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant for enqueue_idempotent_batch default impl, got {err:?}"
        );
    }

    /// `delete_terminal_prefetch_rows_older_than` default impl surfaces
    /// `Invariant` for the same reason as `enqueue_prefetch_batch` —
    /// a mock that returns `Ok(0)` would silently pass the retention
    /// sweep tests.
    #[tokio::test]
    async fn delete_terminal_prefetch_rows_older_than_default_impl_returns_invariant_error() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let err = repo
            .delete_terminal_prefetch_rows_older_than(Duration::from_secs(86_400 * 7))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant for delete_terminal_prefetch_rows_older_than default impl, got {err:?}"
        );
    }

    /// `delete_terminal_scan_rows_older_than` default impl surfaces
    /// `Invariant` for the same reason as
    /// `delete_terminal_prefetch_rows_older_than` — a mock that returns
    /// `Ok(0)` would silently pass the retention sweep tests.
    #[tokio::test]
    async fn delete_terminal_scan_rows_older_than_default_impl_returns_invariant_error() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let err = repo
            .delete_terminal_scan_rows_older_than(Duration::from_secs(86_400 * 7))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant for delete_terminal_scan_rows_older_than default impl, got {err:?}"
        );
    }

    /// `delete_terminal_other_kind_rows_older_than` default impl
    /// surfaces `Invariant` for the same reason as its two siblings — a
    /// mock that returned `Ok(0)` would let a sweep handler report a
    /// successful sweep against a repository that cannot sweep.
    #[tokio::test]
    async fn delete_terminal_other_kind_rows_older_than_default_impl_returns_invariant_error() {
        let repo: Box<dyn JobsRepository> = Box::new(Bare);
        let err = repo
            .delete_terminal_other_kind_rows_older_than(Duration::from_secs(86_400 * 7))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant for delete_terminal_other_kind_rows_older_than default impl, \
             got {err:?}"
        );
    }

    /// `PrefetchEnqueueRow` round-trips by clone + equality. The struct
    /// is the trait's batch-insert payload; the planner pre-builds the
    /// rows before passing them to the adapter.
    #[test]
    fn prefetch_enqueue_row_clone_and_eq() {
        let r1 = PrefetchEnqueueRow {
            kind: "prefetch-dependencies".to_string(),
            params: serde_json::json!({"artifact_id": "0000-…", "current_depth": 1}),
            priority: 0,
            trigger_source: "prefetch".to_string(),
            target_key: "00000000-0000-0000-0000-000000000000|npm|express|1.2.3".to_string(),
        };
        let r2 = r1.clone();
        assert_eq!(r1, r2);
    }

    /// `IdempotentEnqueueRow` round-trips by clone + equality, and two
    /// rows differing only in the dedup key are NOT equal — the field
    /// that decides which rows the unique index collapses must
    /// participate in equality, or a test asserting "the cohort carried
    /// these keys" could pass on the wrong keys.
    #[test]
    fn idempotent_enqueue_row_clone_and_eq() {
        let r1 = IdempotentEnqueueRow {
            kind: "oci-index-child-ingest".to_string(),
            params: serde_json::json!({"repository_id": "0000-…", "depth": 0}),
            priority: 0,
            trigger_source: "ingest".to_string(),
            idempotency_key: IdempotencyKey::try_from(
                "oci-index-child-ingest:00000000-0000-0000-0000-000000000000:abc".to_string(),
            )
            .expect("valid idempotency key"),
        };
        let r2 = r1.clone();
        assert_eq!(r1, r2);

        let mut r3 = r1.clone();
        r3.idempotency_key = IdempotencyKey::try_from(
            "oci-index-child-ingest:00000000-0000-0000-0000-000000000000:def".to_string(),
        )
        .expect("valid idempotency key");
        assert_ne!(r1, r3);
    }
    // -----------------------------------------------------------------
    // Abandoned-lease requeue policy — exhaustiveness guard
    // -----------------------------------------------------------------

    /// Every `jobs.kind` is classified exactly once.
    ///
    /// The sweep's `kind = ANY(...)` filter is an allow-list, so a kind
    /// missing from both constants silently inherits "never requeued" —
    /// the failure mode is a kind whose abandoned rows are stranded
    /// forever with nobody having decided that. Asserting the union
    /// against `EVENT_TASK_KINDS` (the mirror of the `jobs.kind` SQL
    /// CHECK, itself pinned to the migration by
    /// `task_kind_check_lockstep_guard`) turns adding a kind into a
    /// failing test until someone takes a position on it. Modelled on
    /// the no-wildcard exhaustiveness of `retention_registration_guard`.
    #[test]
    fn requeue_policy_is_exhaustive_over_event_task_kinds() {
        use crate::events::EVENT_TASK_KINDS;
        use std::collections::BTreeSet;

        let requeue: BTreeSet<&str> = REQUEUE_ON_LEASE_EXPIRY_KINDS.iter().copied().collect();
        let excluded: BTreeSet<&str> = NO_REQUEUE_ON_LEASE_EXPIRY_KINDS.iter().copied().collect();
        let all: BTreeSet<&str> = EVENT_TASK_KINDS.iter().copied().collect();

        assert_eq!(
            requeue.len(),
            REQUEUE_ON_LEASE_EXPIRY_KINDS.len(),
            "REQUEUE_ON_LEASE_EXPIRY_KINDS contains a duplicate"
        );
        assert_eq!(
            excluded.len(),
            NO_REQUEUE_ON_LEASE_EXPIRY_KINDS.len(),
            "NO_REQUEUE_ON_LEASE_EXPIRY_KINDS contains a duplicate"
        );

        let both: Vec<&&str> = requeue.intersection(&excluded).collect();
        assert!(
            both.is_empty(),
            "a kind cannot be both requeued and excluded: {both:?}"
        );

        let union: BTreeSet<&str> = requeue.union(&excluded).copied().collect();
        let unclassified: Vec<&&str> = all.difference(&union).collect();
        assert!(
            unclassified.is_empty(),
            "jobs.kind value(s) {unclassified:?} are in EVENT_TASK_KINDS but classified by \
             neither REQUEUE_ON_LEASE_EXPIRY_KINDS nor NO_REQUEUE_ON_LEASE_EXPIRY_KINDS — \
             decide whether a concurrent second execution of the kind is absorbed by \
             something, and add it to the matching list with the reason"
        );
        let unknown: Vec<&&str> = union.difference(&all).collect();
        assert!(
            unknown.is_empty(),
            "{unknown:?} is classified by the requeue policy but is not a valid jobs.kind \
             (absent from EVENT_TASK_KINDS) — a renamed or removed kind left a stale entry"
        );
    }

    /// The destructive tier is never requeued.
    ///
    /// `DESTRUCTIVE_TASK_KINDS` is the set whose invocation is
    /// irreversible; the sweep re-driving one of them without the
    /// operator asking is exactly the authority the ADR 0028 idempotency
    /// layer exists to withhold. Pinned separately from the census so a
    /// future edit to the requeue list cannot quietly pull one in.
    #[test]
    fn destructive_kinds_are_never_requeued() {
        use crate::events::DESTRUCTIVE_TASK_KINDS;
        for kind in DESTRUCTIVE_TASK_KINDS {
            assert!(
                NO_REQUEUE_ON_LEASE_EXPIRY_KINDS.contains(kind),
                "destructive kind {kind:?} must be excluded from the abandoned-lease requeue"
            );
            assert!(
                !REQUEUE_ON_LEASE_EXPIRY_KINDS.contains(kind),
                "destructive kind {kind:?} must not be requeued on lease expiry"
            );
        }
    }

    /// Every kind that an `status IN ('pending','running')` uniqueness
    /// index or read can strand permanently IS requeued.
    ///
    /// This is the other half of the exhaustiveness guard and the one
    /// that carries the cost: for these four kinds an abandoned row is
    /// not clutter, it is a capability lost for good — no further `scan`
    /// row for that artifact (`jobs_scan_unique`), no further verify
    /// (`find_active_provenance_for_artifact`), no further pull of that
    /// coordinate (`jobs_prefetch_unique` /
    /// `jobs_prefetch_dependencies_unique`). Excluding one of them would
    /// be trading a capability away, not a row.
    #[test]
    fn kinds_with_an_in_flight_uniqueness_blocker_are_requeued() {
        for kind in [
            "scan",
            "provenance-verify",
            "prefetch",
            "prefetch-dependencies",
        ] {
            assert!(
                REQUEUE_ON_LEASE_EXPIRY_KINDS.contains(&kind),
                "{kind:?} is gated by an in-flight uniqueness predicate, so an abandoned \
                 running row strands it permanently — it must be requeued"
            );
        }
    }

    /// `RequeuedJob` / `RequeueOutcome` round-trip by clone + equality.
    #[test]
    fn requeued_job_clone_and_eq() {
        let j = RequeuedJob {
            id: Uuid::nil(),
            kind: "scan".to_string(),
            attempts: 2,
            outcome: RequeueOutcome::Requeued,
        };
        assert_eq!(j, j.clone());
        let mut other = j.clone();
        other.outcome = RequeueOutcome::RetriesExhausted;
        assert_ne!(j, other);
        assert_eq!(
            format!("{:?}", RequeueOutcome::RetriesExhausted),
            "RetriesExhausted"
        );
    }
}
