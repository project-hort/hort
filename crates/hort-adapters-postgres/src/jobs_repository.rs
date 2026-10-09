//! PostgreSQL implementation of [`JobsRepository`] — the cross-kind
//! `jobs` table from migration 009.
//!
//! The adapter only handles `kind='scan'` rows here. Cross-kind dispatch
//! (other kinds) reuses the same table through a sibling repository —
//! the `kind` column makes the two callers' SELECTs disjoint.

use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::postgres::types::PgInterval;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::jobs_repository::{
    EnqueueOutcome, JobRow, JobStatus, JobsRepository, KindFields, ListJobsFilter, ListJobsPage,
    PendingKindBacklog, RequeueOutcome, RequeuedJob, ScanJob, ScanKindFields, TriggerSource,
};
use hort_domain::types::{ContentHash, IdempotencyKey};
use serde_json::Value as JsonValue;

use crate::{map_sqlx_error, BoxFuture};

/// In-tx `kind='scan'` enqueue — the transactional sibling of
/// [`JobsRepository::enqueue_scan`]. Used by
/// `PgArtifactLifecycle::commit_transition_with_enqueues` to land the scan
/// job inside the **same** transaction as the ingest transition, so no
/// `ScanRequested` event is ever left without its `jobs` row (ADR 0002/0004
/// no-strand).
///
/// **Idempotent.** `ON CONFLICT DO NOTHING` against the `jobs_scan_unique`
/// partial-unique index (`(artifact_id) WHERE kind='scan'`): a pre-existing
/// scan job is a benign no-op, NOT a rollback — re-ingesting an artifact that
/// already has a queued scan must not fail the transition. (A `'scan'` insert
/// can only collide on that one index — `idempotency_key` is NULL here and its
/// unique index is `WHERE idempotency_key IS NOT NULL` — so the bare target is
/// exact.)
pub(crate) async fn enqueue_scan_in_tx(
    tx: &mut sqlx::PgConnection,
    artifact_id: Uuid,
    repository_id: Uuid,
    content_hash: &ContentHash,
    format: &str,
    priority: i16,
    trigger_source: &str,
) -> DomainResult<()> {
    sqlx::query(
        "INSERT INTO public.jobs\n\
             (kind, artifact_id, repository_id, content_hash, format,\n\
              priority, trigger_source, status)\n\
         VALUES ('scan', $1, $2, $3, $4, $5, $6, 'pending')\n\
         ON CONFLICT DO NOTHING",
    )
    .bind(artifact_id)
    .bind(repository_id)
    .bind(content_hash.to_string())
    .bind(format)
    .bind(priority)
    .bind(trigger_source)
    .execute(tx)
    .await
    .map(|_| ())
    .map_err(|e| map_sqlx_error(&e, "ScanJob", &artifact_id.to_string()))
}

/// In-tx `kind='provenance-verify'` enqueue — the transactional sibling of the
/// `enqueue_task("provenance-verify", …)` ingest path. Used by
/// `commit_transition_with_enqueues`. `params` is `{"artifact_id": …}`; there
/// is no idempotency key (one verify per ingest), so the insert always proceeds
/// (a re-ingest adds a fresh verify job, which is harmless — the verifier is
/// idempotent on the artifact). A failure here rolls back the ingest transition.
pub(crate) async fn enqueue_provenance_verify_in_tx(
    tx: &mut sqlx::PgConnection,
    artifact_id: Uuid,
    priority: i16,
    trigger_source: &str,
) -> DomainResult<()> {
    let params = serde_json::json!({ "artifact_id": artifact_id });
    sqlx::query(
        "INSERT INTO public.jobs\n\
             (kind, params, actor_id, priority, trigger_source, status)\n\
         VALUES ('provenance-verify', $1, NULL, $2, $3, 'pending')",
    )
    .bind(params)
    .bind(priority)
    .bind(trigger_source)
    .execute(tx)
    .await
    .map(|_| ())
    .map_err(|e| map_sqlx_error(&e, "ProvenanceVerifyJob", &artifact_id.to_string()))
}

/// Multi-kind claim query (used by `claim_pending_by_kinds`).
///
/// Lifted out of the function body so the inline test
/// [`claim_pending_by_kinds_sql_has_no_token_mashing`] can pin its
/// shape — a previous version of this query used bare `\` line
/// continuations (no leading `\n`), which eat both the newline AND
/// the following indent. That collapsed adjacent SQL tokens
/// (`public.jobs` + `WHERE`, `'pending'` + `AND`, ...) and Postgres
/// rejected every poll with `syntax error at or near "="`. Every line
/// here MUST end with `\n\` (explicit newline + line continuation) so
/// the constructed string carries actual newlines into the query.
///
/// The `RETURNING` clause MUST include the four scan-typed columns
/// (`artifact_id`, `repository_id`, `content_hash`, `format`) so that
/// `kind='scan'` rows can be projected into [`KindFields::Scan`]. An
/// earlier version omitted them and every claimed scan failed with
/// `artifact_id is NULL in claim_pending_by_kinds result`; the
/// regression is pinned by
/// [`claim_pending_by_kinds_sql_returning_includes_scan_typed_columns`].
///
/// Reserved-oldest-slot fairness shape: `oldest` claims exactly one row —
/// the single globally oldest eligible row across every registered kind,
/// ordered by `created_at ASC` alone (priority-blind) — while `ranked`
/// claims the remaining `batch_size - 1` slots by the pre-existing
/// `priority DESC, created_at ASC` order, explicitly excluding whatever
/// `oldest` already picked so the same row is never claimed twice. Without
/// the reserved slot, a sustained high-priority stream of the same kind can
/// starve an old low-priority row indefinitely; the reserved slot bounds
/// that wait to roughly one batch-drain cycle regardless of priority.
/// `oldest` is `MATERIALIZED` deliberately: it is referenced twice (by
/// `ranked`'s exclusion and by `claimed`'s union), and the default
/// multiply-referenced-CTE materialization is exactly what is wanted here —
/// spelling it out guards against a future edit that drops a reference and
/// silently flips the default to inlining, which would re-run the `FOR
/// UPDATE SKIP LOCKED` select twice and risk locking two different rows
/// instead of reusing the one already picked. `LEAST($2, 1)` /
/// `GREATEST($2 - 1, 0)` degrade to claiming nothing when `batch_size` is
/// 0, matching the pre-existing `LIMIT $2` behavior instead of always
/// locking one row regardless of the caller's requested batch size.
const CLAIM_PENDING_BY_KINDS_SQL: &str = "WITH oldest AS MATERIALIZED (\n\
                     SELECT id FROM public.jobs\n\
                     WHERE status = 'pending'\n\
                       AND kind = ANY($1::text[])\n\
                       AND (locked_until IS NULL OR locked_until < now())\n\
                     ORDER BY created_at ASC, id ASC\n\
                     FOR UPDATE SKIP LOCKED\n\
                     LIMIT LEAST($2, 1)\n\
                 ),\n\
                 ranked AS (\n\
                     SELECT id FROM public.jobs\n\
                     WHERE status = 'pending'\n\
                       AND kind = ANY($1::text[])\n\
                       AND (locked_until IS NULL OR locked_until < now())\n\
                       AND id NOT IN (SELECT id FROM oldest)\n\
                     ORDER BY priority DESC, created_at ASC\n\
                     FOR UPDATE SKIP LOCKED\n\
                     LIMIT GREATEST($2 - 1, 0)\n\
                 ),\n\
                 claimed AS (\n\
                     SELECT id FROM oldest\n\
                     UNION ALL\n\
                     SELECT id FROM ranked\n\
                 )\n\
                 UPDATE public.jobs SET\n\
                     status = 'running',\n\
                     locked_by = $3,\n\
                     locked_until = now() + $4,\n\
                     attempts = attempts + 1,\n\
                     updated_at = now()\n\
                 WHERE id IN (SELECT id FROM claimed)\n\
                 RETURNING id, kind, status, params, actor_id, priority, trigger_source,\n\
                     attempts, created_at, updated_at, completed_at, last_error, result_summary,\n\
                     artifact_id, repository_id, content_hash, format";

/// Not-before applied to a row the abandoned-lease sweep returns to
/// `pending`.
///
/// Exists for the same reason the dispatcher's `return_to_pending`
/// gives an undispatchable row a backoff at all: the sweeping replica is
/// also a claiming replica, and a row released with a NULL lease is
/// eligible on that same replica's very next poll. A worker killed by
/// the task itself (an OOM on one oversized artifact) would then re-take
/// the row immediately and die again, spending the whole attempt budget
/// inside one sweep interval instead of across several.
///
/// Flat rather than exponential: the row has already waited a full lease
/// plus the grace before it gets here, so the purpose of this delay is
/// only to break the same-replica re-grab, and the attempt cap — not the
/// spacing — is what bounds a crash loop.
///
/// Deliberately **not** the retry curve's first interval
/// (`hort_app::retry_backoff::compute_backoff`, 60 s). That curve sets
/// how long the system tolerates a dependency that keeps failing; this
/// number only has to outlast one poll interval, and the lease plus its
/// grace — half an hour at the defaults — has already supplied every
/// bit of patience this row needs.
const REQUEUE_BACKOFF: Duration = Duration::from_secs(30);

/// `last_error` written onto a row the abandoned-lease sweep resolves.
///
/// Operator-facing: it is the only record of why a row that no handler
/// ever reported on changed state, and it has to read as a diagnosis
/// rather than as a handler's own failure message.
const REQUEUE_LAST_ERROR: &str =
    "claim lease expired past the grace window without renewal — the worker holding this row      stopped heartbeating and is presumed dead";

/// `UPDATE` behind [`JobsRepository::renew_lease`].
///
/// Three predicates, all load-bearing:
/// - `id = $1` picks the row.
/// - `locked_by = $2` is the fence. A renewal from a worker that no
///   longer holds the claim (the abandoned-lease sweep requeued it and a
///   sibling re-claimed it) must not extend someone else's lease — and
///   the zero-rows-updated result is how the losing worker finds out its
///   execution is no longer the authoritative one.
/// - `status = 'running'` keeps a renewal that races the outcome write
///   from resurrecting a lease on an already-terminal row, which would
///   otherwise leave a `completed` row carrying a future `locked_until`
///   and make the sweep's own predicate ambiguous.
const RENEW_LEASE_SQL: &str = "UPDATE public.jobs SET\n\
                     locked_until = now() + $3,\n\
                     updated_at = now()\n\
                 WHERE id = $1\n\
                   AND locked_by = $2\n\
                   AND status = 'running'";

/// `UPDATE` behind [`JobsRepository::requeue_abandoned`] — the
/// abandoned-lease sweep.
///
/// Shape notes for anyone editing this string:
///
/// - The picking CTE mirrors the claim's `FOR UPDATE SKIP LOCKED` +
///   `LIMIT`, so two workers sweeping at the same tick take disjoint
///   rows instead of blocking on each other. The sweep is safe to run on
///   every replica; it needs no leader election.
/// - `locked_until IS NOT NULL` is not redundant with the comparison. A
///   `running` row with a NULL lease cannot have been produced by either
///   claim statement, and treating "no lease" as "lease long expired"
///   would sweep a row whose history nobody understands.
/// - `now() - $2::interval` is the grace on top of the lapse. With lease
///   renewal running at a third of the lease, a live worker is at most a
///   third of a lease stale, so a grace of one full lease is the margin
///   that absorbs a renewal that lost a DB race, a paused container, and
///   a mixed-version fleet whose older replicas do not renew at all.
/// - The `CASE` is the retry budget, and this statement is the only
///   place it can be spent for a row whose handler never returned. Below
///   the cap the row goes back to `pending` with a short not-before so
///   the sweeping replica does not immediately re-claim what it just
///   released; at the cap it goes to `failed`, which for `kind='scan'`
///   hands the artifact to the stranded-scan recovery sweep — a `failed`
///   newest scan job is exactly what `select_stranded` re-picks.
/// - `attempts` is deliberately untouched: the next claim increments it,
///   so the budget is spent by execution attempts, not by sweeps.
/// - The row is updated, never deleted. A late `mark_completed` from the
///   original worker is `WHERE id = $1` with no status predicate, so it
///   still lands on the surviving row rather than updating nothing.
const REQUEUE_ABANDONED_SQL: &str = "WITH abandoned AS (\n\
                     SELECT id FROM public.jobs\n\
                     WHERE status = 'running'\n\
                       AND kind = ANY($1::text[])\n\
                       AND locked_until IS NOT NULL\n\
                       AND locked_until < now() - $2::interval\n\
                     ORDER BY locked_until ASC, id ASC\n\
                     FOR UPDATE SKIP LOCKED\n\
                     LIMIT $3\n\
                 )\n\
                 UPDATE public.jobs j SET\n\
                     status = CASE WHEN j.attempts >= $4 THEN 'failed' ELSE 'pending' END,\n\
                     locked_by = NULL,\n\
                     locked_until = CASE WHEN j.attempts >= $4 THEN NULL\n\
                                         ELSE now() + $5 END,\n\
                     last_error = $6,\n\
                     updated_at = now()\n\
                 FROM abandoned a\n\
                 WHERE j.id = a.id\n\
                 RETURNING j.id, j.kind, j.attempts, j.status";

/// `DELETE` behind [`JobsRepository::delete_terminal_prefetch_rows_older_than`]
/// — the pull-through ingest cascade's rows, none of which hold durable
/// state. The port doc carries the full rationale; the load-bearing
/// details for anyone editing this string:
///
/// - **`prefetch-tick` is carved out by name.** It matches
///   `kind LIKE 'prefetch%'` but is a scheduled tick, not cascade work,
///   and its newest `completed` row's `result_summary` holds the
///   rotation's keyset cursor (read back by
///   [`JobsRepository::last_result_summary_by_kind`]). This sweep has no
///   keep-newest clause — it does not need one, because with the carve-out
///   every row it reaches really is stateless — so deleting a
///   `prefetch-tick` row here would restart the rotation from the
///   beginning. The kind is swept by
///   [`JobsRepository::delete_terminal_other_kind_rows_older_than`]
///   instead, which retains the newest `completed` row per kind.
/// - The carve-out must stay the exact mirror image of the generic
///   sweep's `OR kind = 'prefetch-tick'` admission, or the kind is either
///   swept twice on two horizons or never swept at all. Pinned DB-free by
///   `the_two_sweeps_partition_the_prefetch_prefix`.
/// - Kept as a named constant so those DB-free tests can read the
///   predicate without a database.
const DELETE_TERMINAL_PREFETCH_ROWS_SQL: &str = "DELETE FROM public.jobs\n\
                 WHERE ((kind LIKE 'prefetch%' AND kind <> 'prefetch-tick')\n\
                        OR kind = 'oci-index-child-ingest')\n\
                   AND status IN ('completed', 'failed')\n\
                   AND updated_at < now() - $1::interval";

/// `DELETE` behind [`JobsRepository::delete_terminal_other_kind_rows_older_than`]
/// — the horizon for every `jobs.kind` the two kind-specific sweeps do not
/// reach. The port doc carries the full rationale; the load-bearing details
/// for anyone editing this string:
///
/// - The kind predicate is the **textual complement** of the two sibling
///   sweeps (`NOT LIKE 'prefetch%'` with `prefetch-tick` readmitted,
///   `NOT IN ('scan', 'oci-index-child-ingest')`), so exactly one sweep
///   is ever in force per kind and a future `prefetch%` kind needs no
///   edit here.
/// - `OR kind = 'prefetch-tick'` readmits the one `prefetch%` kind the
///   cascade sweep carves out. That kind's newest `completed` row carries
///   the rotation's keyset cursor, so it needs the keep-newest clause
///   below; the cascade sweep has none. The two predicates must stay
///   mirror images — pinned DB-free by
///   `the_two_sweeps_partition_the_prefetch_prefix`.
/// - The `live` CTE aggregates over **all** terminal rows of a kind, not
///   only the aged ones. Aggregating over the aged subset instead would
///   retain "the newest row that happened to be old", which is a
///   different row that never ages out.
/// - Two rows per kind survive, not one: the newest `completed` row
///   (what `max(completed_at)` / `ORDER BY completed_at DESC LIMIT 1`
///   readers read) and the newest terminal row by `created_at` (what an
///   `ORDER BY created_at DESC LIMIT 1` reader reads). Dropping the
///   `completed` half would answer "never ran" for a task whose newest
///   terminal row is a failure.
/// - Kept as a named constant so the DB-free
///   `delete_terminal_other_kind_rows_sql_*` tests can pin those
///   invariants without a database.
const DELETE_TERMINAL_OTHER_KIND_ROWS_SQL: &str = "WITH live AS (\n\
                     SELECT kind,\n\
                            max(completed_at) FILTER (WHERE status = 'completed')\n\
                              AS newest_completed_at,\n\
                            max(created_at) AS newest_created_at\n\
                     FROM public.jobs\n\
                     WHERE status IN ('completed', 'failed')\n\
                       AND (kind NOT LIKE 'prefetch%' OR kind = 'prefetch-tick')\n\
                       AND kind NOT IN ('scan', 'oci-index-child-ingest')\n\
                     GROUP BY kind\n\
                 )\n\
                 DELETE FROM public.jobs j\n\
                 USING live l\n\
                 WHERE l.kind = j.kind\n\
                   AND j.status IN ('completed', 'failed')\n\
                   AND j.updated_at < now() - $1::interval\n\
                   AND NOT (j.status = 'completed'\n\
                            AND j.completed_at IS NOT DISTINCT FROM l.newest_completed_at)\n\
                   AND j.created_at <> l.newest_created_at";

/// PostgreSQL adapter for [`JobsRepository`].
pub struct PgJobsRepository {
    pool: PgPool,
}

impl PgJobsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Return the id of an in-flight `kind='scan'` row (status
    /// `'pending'` or `'running'`) for `artifact_id`, or `None` if no
    /// such row exists.
    ///
    /// Powers `ManualRescanUseCase::trigger`'s "409 only on in-flight"
    /// check. A completed or failed scan row is intentionally NOT
    /// returned — those are eligible for a fresh rescan via the partial
    /// unique index `jobs_scan_unique`'s status-filtered shape.
    async fn find_active_scan_for_artifact_impl(
        &self,
        artifact_id: Uuid,
    ) -> DomainResult<Option<Uuid>> {
        let id_opt: Option<Uuid> = sqlx::query_scalar(
            "SELECT id \
             FROM public.jobs \
             WHERE kind = 'scan' \
               AND artifact_id = $1 \
               AND status IN ('pending', 'running') \
             LIMIT 1",
        )
        .bind(artifact_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_sqlx_error(&e, "ScanJob", &artifact_id.to_string()))?;
        Ok(id_opt)
    }

    /// Return the id of an in-flight `kind='provenance-verify'` row
    /// (status `'pending'` or `'running'`) for `artifact_id`, or `None`
    /// when no such row exists.
    ///
    /// Powers the expiry backstop's per-tick dedup
    /// (`QuarantineUseCase::release_expired`): a `Required` + `Pending`
    /// candidate enqueues a final verify only when none is already
    /// in-flight, so repeated sweep ticks between the enqueue and the
    /// worker running it do not pile up duplicate open rows.
    ///
    /// `provenance-verify` rows carry `artifact_id` inside the `params`
    /// JSONB (`{"artifact_id": …}`), NOT the scan-typed `artifact_id`
    /// column (see `enqueue_provenance_verify_in_tx` +
    /// `enqueue_task("provenance-verify", …)`), so the predicate matches
    /// on `params->>'artifact_id'`.
    async fn find_active_provenance_for_artifact_impl(
        &self,
        artifact_id: Uuid,
    ) -> DomainResult<Option<Uuid>> {
        let id_opt: Option<Uuid> = sqlx::query_scalar(
            "SELECT id \
             FROM public.jobs \
             WHERE kind = 'provenance-verify' \
               AND params->>'artifact_id' = $1 \
               AND status IN ('pending', 'running') \
             LIMIT 1",
        )
        .bind(artifact_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_sqlx_error(&e, "ProvenanceVerifyJob", &artifact_id.to_string()))?;
        Ok(id_opt)
    }
}

/// Emitted once per claimed row that failed [`row_to_job_row`]
/// projection and was resolved terminally instead of being stranded in
/// `running`. See `docs/metrics-catalog.md`.
const METRIC_CLAIM_UNMAPPABLE: &str = "hort_admin_tasks_claim_unmappable_total";

/// PostgreSQL `unique_violation` SQLSTATE — surfaced when the partial
/// unique on `(artifact_id) WHERE kind='scan'` rejects a duplicate
/// `enqueue_scan`.
const SQLSTATE_UNIQUE_VIOLATION: &str = "23505";

/// Convert a `Duration` to a `PgInterval` for `now() + $::interval`
/// arithmetic. The intermediate cast is bounded — clamping to `i64::MAX`
/// microseconds (~292,000 years) is safer than `unwrap`-ing on overflow.
fn duration_to_pg_interval(d: Duration) -> PgInterval {
    let micros: i64 = d.as_micros().try_into().unwrap_or(i64::MAX);
    PgInterval {
        months: 0,
        days: 0,
        microseconds: micros,
    }
}

/// Map a row to a [`ScanJob`]. The row must have ALL columns the
/// claim/insert queries return — otherwise we surface
/// [`DomainError::Invariant`] (the schema and SELECT clause are owned
/// by this adapter; mismatch is a bug, not an operator-facing error).
fn row_to_scan_job(row: &sqlx::postgres::PgRow) -> DomainResult<ScanJob> {
    let id: Uuid = row.try_get("id").map_err(|e| invariant(&e))?;
    let artifact_id: Option<Uuid> = row.try_get("artifact_id").map_err(|e| invariant(&e))?;
    let artifact_id = artifact_id.ok_or_else(|| {
        DomainError::Invariant(format!("jobs row {id}: kind='scan' has NULL artifact_id"))
    })?;
    let repository_id: Option<Uuid> = row.try_get("repository_id").map_err(|e| invariant(&e))?;
    let repository_id = repository_id.ok_or_else(|| {
        DomainError::Invariant(format!("jobs row {id}: kind='scan' has NULL repository_id"))
    })?;
    let content_hash_str: Option<String> =
        row.try_get("content_hash").map_err(|e| invariant(&e))?;
    let content_hash_str = content_hash_str.ok_or_else(|| {
        DomainError::Invariant(format!("jobs row {id}: kind='scan' has NULL content_hash"))
    })?;
    let content_hash = ContentHash::from_str(&content_hash_str).map_err(|e| {
        DomainError::Invariant(format!(
            "jobs row {id}: content_hash {content_hash_str:?} not a valid SHA-256: {e}"
        ))
    })?;
    let format_opt: Option<String> = row.try_get("format").map_err(|e| invariant(&e))?;
    let format = format_opt.ok_or_else(|| {
        DomainError::Invariant(format!("jobs row {id}: kind='scan' has NULL format"))
    })?;
    let status_str: String = row.try_get("status").map_err(|e| invariant(&e))?;
    let status = match status_str.as_str() {
        "pending" => JobStatus::Pending,
        "running" => JobStatus::Running,
        "completed" => JobStatus::Completed,
        "failed" => JobStatus::Failed,
        other => {
            return Err(DomainError::Invariant(format!(
                "jobs row {id}: unknown status '{other}'"
            )));
        }
    };
    let attempts_i32: i32 = row.try_get("attempts").map_err(|e| invariant(&e))?;
    let attempts = u32::try_from(attempts_i32).map_err(|_| {
        DomainError::Invariant(format!(
            "jobs row {id}: attempts is negative ({attempts_i32})"
        ))
    })?;
    let locked_by: Option<String> = row.try_get("locked_by").map_err(|e| invariant(&e))?;
    let locked_until: Option<DateTime<Utc>> =
        row.try_get("locked_until").map_err(|e| invariant(&e))?;
    let last_error: Option<String> = row.try_get("last_error").map_err(|e| invariant(&e))?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(|e| invariant(&e))?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(|e| invariant(&e))?;
    let priority_i16: i16 = row.try_get("priority").map_err(|e| invariant(&e))?;
    // `priority` is `smallint NOT NULL` with a `BETWEEN 0 AND 100`
    // CHECK in migration 009. The ScanJob struct stores `u8` because
    // the CHECK already bounds the range below `u8::MAX` — anything
    // outside that window is a schema-drift bug, not an operator
    // input.
    let priority = u8::try_from(priority_i16).map_err(|_| {
        DomainError::Invariant(format!(
            "jobs row {id}: priority {priority_i16} outside u8 range"
        ))
    })?;
    let trigger_source_str: String = row.try_get("trigger_source").map_err(|e| invariant(&e))?;
    let trigger_source = TriggerSource::from_str(&trigger_source_str).map_err(|e| {
        DomainError::Invariant(format!(
            "jobs row {id}: trigger_source {trigger_source_str:?} not a known literal: {e}"
        ))
    })?;
    Ok(ScanJob {
        id,
        artifact_id,
        repository_id,
        content_hash,
        format,
        status,
        attempts,
        locked_by,
        locked_until,
        last_error,
        created_at,
        updated_at,
        trigger_source,
        priority,
    })
}

fn invariant(e: &sqlx::Error) -> DomainError {
    DomainError::Invariant(format!("jobs row decode failed: {e}"))
}

/// Map a generic cross-kind jobs row to a [`JobRow`].
fn row_to_job_row(row: &sqlx::postgres::PgRow) -> DomainResult<JobRow> {
    let id: Uuid = row.try_get("id").map_err(|e| invariant(&e))?;
    let kind: String = row.try_get("kind").map_err(|e| invariant(&e))?;
    let status_str: String = row.try_get("status").map_err(|e| invariant(&e))?;
    let status = match status_str.as_str() {
        "pending" => JobStatus::Pending,
        "running" => JobStatus::Running,
        "completed" => JobStatus::Completed,
        "failed" => JobStatus::Failed,
        other => {
            return Err(DomainError::Invariant(format!(
                "jobs row {id}: unknown status '{other}'"
            )));
        }
    };
    let params: Option<JsonValue> = row
        .try_get::<Option<JsonValue>, _>("params")
        .map_err(|e| invariant(&e))?;
    let actor_id: Option<Uuid> = row.try_get("actor_id").map_err(|e| invariant(&e))?;
    let priority: i16 = row.try_get("priority").map_err(|e| invariant(&e))?;
    let trigger_source: String = row.try_get("trigger_source").map_err(|e| invariant(&e))?;
    let attempts_i32: i32 = row.try_get("attempts").map_err(|e| invariant(&e))?;
    let attempts = u32::try_from(attempts_i32).map_err(|_| {
        DomainError::Invariant(format!(
            "jobs row {id}: attempts is negative ({attempts_i32})"
        ))
    })?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(|e| invariant(&e))?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(|e| invariant(&e))?;
    let completed_at: Option<DateTime<Utc>> =
        row.try_get("completed_at").map_err(|e| invariant(&e))?;
    let last_error: Option<String> = row.try_get("last_error").map_err(|e| invariant(&e))?;
    // `result_summary` is a `jsonb` column (migration 009), written by
    // `mark_completed` as a `serde_json::Value` — decode it as the same
    // type. Decoding it as `String` is a sqlx type mismatch (TEXT vs
    // JSONB) that errors on every non-NULL value, which 500'd the
    // admin-task read path for every completed job. Mirrors the `params`
    // jsonb decode above.
    let result_summary: Option<JsonValue> =
        row.try_get("result_summary").map_err(|e| invariant(&e))?;

    // Scan-typed columns. For `kind='scan'` rows these are populated by
    // the schema (migration 009 CHECK); for other kinds they are SQL
    // NULL. A `ColumnNotFound` from sqlx here means the query's
    // RETURNING/SELECT clause omitted the column — `try_get` returns
    // that as an `Err`, and we propagate it untouched so the row mapper
    // surfaces the projection bug. The previous implementation used
    // `unwrap_or(None)` and silently dropped the missing-column signal,
    // which is exactly how the `artifact_id IS NULL` regression slipped
    // past code review.
    let artifact_id: Option<Uuid> = row.try_get("artifact_id").map_err(|e| invariant(&e))?;
    let repository_id: Option<Uuid> = row.try_get("repository_id").map_err(|e| invariant(&e))?;
    let content_hash_str: Option<String> =
        row.try_get("content_hash").map_err(|e| invariant(&e))?;
    let content_hash = content_hash_str
        .as_deref()
        .map(ContentHash::from_str)
        .transpose()
        .map_err(|e| {
            DomainError::Invariant(format!(
                "jobs row {id}: content_hash not a valid SHA-256: {e}"
            ))
        })?;
    let format: Option<String> = row.try_get("format").map_err(|e| invariant(&e))?;

    let kind_fields =
        decide_kind_fields(id, &kind, artifact_id, repository_id, content_hash, format)?;

    Ok(JobRow {
        id,
        kind,
        status,
        params,
        actor_id,
        priority,
        trigger_source,
        attempts,
        created_at,
        updated_at,
        completed_at,
        last_error,
        result_summary,
        kind_fields,
    })
}

/// Project raw optional scan-typed columns into a typed [`KindFields`].
///
/// `kind='scan'` rows require all four scan-typed columns to be present
/// (schema CHECK in migration 009). When a query's `RETURNING` /
/// `SELECT` clause forgets to project one of them, `row_to_job_row`
/// receives `None` for the missing column and this function refuses
/// to build a half-populated row — surfaced as
/// `DomainError::Invariant` with a message naming the offending column
/// and the row id, so an operator can locate the offending query.
///
/// For any non-`scan` kind, the function returns
/// [`KindFields::Other`] regardless of whether the optional columns
/// were populated (they're NULL on the database side for those kinds).
fn decide_kind_fields(
    job_id: Uuid,
    kind: &str,
    artifact_id: Option<Uuid>,
    repository_id: Option<Uuid>,
    content_hash: Option<ContentHash>,
    format: Option<String>,
) -> DomainResult<KindFields> {
    if kind != "scan" {
        return Ok(KindFields::Other);
    }
    let artifact_id = artifact_id.ok_or_else(|| {
        DomainError::Invariant(format!(
            "jobs row {job_id}: kind='scan' but artifact_id was NULL/unprojected \
             (RETURNING/SELECT clause missing the `artifact_id` column?)"
        ))
    })?;
    let repository_id = repository_id.ok_or_else(|| {
        DomainError::Invariant(format!(
            "jobs row {job_id}: kind='scan' but repository_id was NULL/unprojected"
        ))
    })?;
    let content_hash = content_hash.ok_or_else(|| {
        DomainError::Invariant(format!(
            "jobs row {job_id}: kind='scan' but content_hash was NULL/unprojected"
        ))
    })?;
    let format = format.ok_or_else(|| {
        DomainError::Invariant(format!(
            "jobs row {job_id}: kind='scan' but format was NULL/unprojected"
        ))
    })?;
    Ok(KindFields::Scan(ScanKindFields {
        artifact_id,
        repository_id,
        content_hash,
        format,
    }))
}

/// Column list for the post-claim and post-insert RETURNING clauses.
/// Order is consumed positionally by [`row_to_scan_job`] via column
/// names, so additions must update the mapper too.
///
/// `priority` and `trigger_source` are read into the [`ScanJob`]
/// projection so observability emissions can label by trigger and the
/// post-query Rust sort
/// (`sort_claimed_scan_jobs`) can re-establish `priority DESC,
/// created_at ASC` after `UPDATE … RETURNING` — which Postgres does
/// NOT guarantee preserves the picking-CTE's `ORDER BY`.
const RETURNING_COLS: &str = "id, artifact_id, repository_id, content_hash, format, status, \
    attempts, locked_by, locked_until, last_error, created_at, updated_at, priority, \
    trigger_source";

/// Re-establish `priority DESC, created_at ASC` (id ASC tiebreaker)
/// over the rows returned by the `claim_scan_jobs` UPDATE-RETURNING.
///
/// Postgres `UPDATE … RETURNING` returns rows in executor order, NOT
/// in the order chosen by the picking CTE's `ORDER BY`. The CTE's
/// ordering still matters — it's how `FOR UPDATE SKIP LOCKED` decides
/// which rows to lock under contention. But the rows that come back
/// must be re-sorted on the Rust side or downstream code that depends
/// on priority order (workers prioritising `critical`-tagged scans,
/// the integration test pinning the contract) will see arbitrary
/// orderings.
fn sort_claimed_scan_jobs(jobs: &mut [ScanJob]) {
    jobs.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.created_at.cmp(&b.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });
}

fn sort_claimed_jobs(jobs: &mut [JobRow]) {
    jobs.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.created_at.cmp(&b.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });
}

impl JobsRepository for PgJobsRepository {
    fn claim_scan_jobs<'a>(
        &'a self,
        worker_id: &'a str,
        batch_size: u32,
        lock_duration: Duration,
    ) -> BoxFuture<'a, DomainResult<Vec<ScanJob>>> {
        let worker_id = worker_id.to_string();
        let interval = duration_to_pg_interval(lock_duration);
        let limit: i64 = batch_size.into();
        Box::pin(async move {
            tracing::debug!(
                worker_id = %worker_id,
                batch_size,
                "claim_scan_jobs",
            );
            // Two-CTE claim:
            //   1. SELECT pending scan rows whose lock has expired or
            //      never been set, ORDER BY priority DESC, created_at,
            //      FOR UPDATE SKIP LOCKED, LIMIT $batch.
            //   2. UPDATE the picked ids to running + bump attempts,
            //      RETURNING the post-update column set.
            let sql = format!(
                "WITH claimed AS (\n\
                     SELECT id FROM public.jobs\n\
                     WHERE kind = 'scan'\n\
                       AND status = 'pending'\n\
                       AND (locked_until IS NULL OR locked_until < now())\n\
                     ORDER BY priority DESC, created_at\n\
                     FOR UPDATE SKIP LOCKED\n\
                     LIMIT $1\n\
                 )\n\
                 UPDATE public.jobs SET\n\
                     status = 'running',\n\
                     locked_by = $2,\n\
                     locked_until = now() + $3,\n\
                     attempts = attempts + 1,\n\
                     updated_at = now()\n\
                 WHERE id IN (SELECT id FROM claimed)\n\
                 RETURNING {RETURNING_COLS}"
            );
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(limit)
                .bind(&worker_id)
                .bind(interval)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ScanJob", "claim_scan_jobs"))?;
            let mut jobs: Vec<ScanJob> = rows
                .iter()
                .map(row_to_scan_job)
                .collect::<DomainResult<_>>()?;
            sort_claimed_scan_jobs(&mut jobs);
            Ok(jobs)
        })
    }

    fn mark_completed<'a>(
        &'a self,
        job_id: Uuid,
        result_summary: serde_json::Value,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(%job_id, "mark_completed");
            // H17 — persist the handler's `result_summary`. A `Value::Null`
            // summary (the "no summary" sentinel, e.g. a handler that emits
            // its forensics elsewhere) is stored as SQL NULL, not a JSON
            // `'null'`, so `result_summary IS NULL` keeps meaning "no summary".
            let summary: Option<serde_json::Value> = if result_summary.is_null() {
                None
            } else {
                Some(result_summary)
            };
            sqlx::query(
                "UPDATE public.jobs SET\n\
                     status = 'completed',\n\
                     completed_at = now(),\n\
                     result_summary = $2,\n\
                     updated_at = now()\n\
                 WHERE id = $1",
            )
            .bind(job_id)
            .bind(summary)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "ScanJob", &job_id.to_string()))?;
            Ok(())
        })
    }

    fn reschedule<'a>(
        &'a self,
        job_id: Uuid,
        backoff: Duration,
        last_error: &'a str,
    ) -> BoxFuture<'a, DomainResult<()>> {
        let interval = duration_to_pg_interval(backoff);
        let last_error = last_error.to_string();
        Box::pin(async move {
            tracing::debug!(%job_id, "reschedule");
            sqlx::query(
                "UPDATE public.jobs SET\n\
                     status = 'pending',\n\
                     locked_by = NULL,\n\
                     locked_until = now() + $2,\n\
                     last_error = $3,\n\
                     updated_at = now()\n\
                 WHERE id = $1",
            )
            .bind(job_id)
            .bind(interval)
            .bind(&last_error)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "ScanJob", &job_id.to_string()))?;
            Ok(())
        })
    }

    fn mark_failed<'a>(
        &'a self,
        job_id: Uuid,
        last_error: &'a str,
    ) -> BoxFuture<'a, DomainResult<()>> {
        let last_error = last_error.to_string();
        Box::pin(async move {
            tracing::debug!(%job_id, "mark_failed");
            sqlx::query(
                "UPDATE public.jobs SET\n\
                     status = 'failed',\n\
                     last_error = $2,\n\
                     updated_at = now()\n\
                 WHERE id = $1",
            )
            .bind(job_id)
            .bind(&last_error)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "ScanJob", &job_id.to_string()))?;
            Ok(())
        })
    }

    fn find_active_scan_for_artifact<'a>(
        &'a self,
        artifact_id: Uuid,
    ) -> BoxFuture<'a, DomainResult<Option<Uuid>>> {
        Box::pin(self.find_active_scan_for_artifact_impl(artifact_id))
    }

    fn find_active_provenance_for_artifact<'a>(
        &'a self,
        artifact_id: Uuid,
    ) -> BoxFuture<'a, DomainResult<Option<Uuid>>> {
        Box::pin(self.find_active_provenance_for_artifact_impl(artifact_id))
    }

    fn pending_scan_count<'a>(&'a self) -> BoxFuture<'a, DomainResult<i64>> {
        Box::pin(async move {
            tracing::debug!("pending_scan_count");
            // `kind='scan'` rows whose status is `pending` are the
            // natural definition of queue depth (rows waiting for a
            // worker to claim them). `running` rows are excluded
            // because they are already being worked on; `completed`
            // and `failed` rows are terminal.
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM public.jobs \
                 WHERE kind = 'scan' AND status = 'pending'",
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "ScanJob", "pending_scan_count"))?;
            Ok(count)
        })
    }

    fn enqueue_scan<'a>(
        &'a self,
        artifact_id: Uuid,
        repository_id: Uuid,
        content_hash: &'a ContentHash,
        format: &'a str,
        priority: i16,
        trigger_source: &'a str,
    ) -> BoxFuture<'a, DomainResult<Uuid>> {
        let content_hash_str = content_hash.to_string();
        let format = format.to_string();
        let trigger_source = trigger_source.to_string();
        Box::pin(async move {
            tracing::debug!(
                %artifact_id,
                %repository_id,
                priority,
                %trigger_source,
                "enqueue_scan",
            );
            let result: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
                "INSERT INTO public.jobs\n\
                     (kind, artifact_id, repository_id, content_hash, format,\n\
                      priority, trigger_source, status)\n\
                 VALUES ('scan', $1, $2, $3, $4, $5, $6, 'pending')\n\
                 RETURNING id",
            )
            .bind(artifact_id)
            .bind(repository_id)
            .bind(&content_hash_str)
            .bind(&format)
            .bind(priority)
            .bind(&trigger_source)
            .fetch_one(&self.pool)
            .await;
            result.map_err(|e| {
                if let Some(db_err) = e.as_database_error() {
                    if db_err.code().as_deref() == Some(SQLSTATE_UNIQUE_VIOLATION) {
                        return DomainError::Conflict(format!(
                            "scan job already exists for artifact {artifact_id}"
                        ));
                    }
                }
                map_sqlx_error(&e, "ScanJob", &artifact_id.to_string())
            })
        })
    }
    fn enqueue_task<'a>(
        &'a self,
        kind: &'a str,
        params: &'a JsonValue,
        actor_id: Option<Uuid>,
        priority: i16,
        trigger_source: &'a str,
        idempotency_key: Option<&'a IdempotencyKey>,
    ) -> BoxFuture<'a, DomainResult<EnqueueOutcome>> {
        let kind = kind.to_string();
        let params = params.clone();
        let trigger_source = trigger_source.to_string();
        let idempotency_key: Option<String> = idempotency_key.map(|k| k.as_str().to_string());
        Box::pin(async move {
            tracing::debug!(
                %kind,
                %priority,
                %trigger_source,
                idempotency_key = ?idempotency_key,
                "enqueue_task",
            );

            // `ON CONFLICT (idempotency_key) WHERE idempotency_key IS
            // NOT NULL DO NOTHING` against the `jobs_idempotency_key_uq`
            // partial-unique index (ADR 0028). When `idempotency_key` is
            // `None` the partial-unique predicate is inert and the insert
            // always proceeds.
            //
            // The UNION-ALL SELECT recovers the existing row's id on
            // the conflict branch. The `false AS dup` / `true AS dup`
            // computed literals are projected as `Option<bool>` by
            // sqlx (sqlx cannot prove non-nullability of a constant
            // literal across a UNION); `unwrap_or(false)` collapses
            // back to the boolean we encoded.
            //
            // `WHERE idempotency_key = $6 AND NOT EXISTS (SELECT 1
            // FROM ins)` ensures we only run the existing-row lookup
            // when the insert was absorbed by ON CONFLICT — without
            // the `NOT EXISTS`, a same-key sibling row written by an
            // unrelated test could spuriously match. `LIMIT 1` guards
            // against the partial-unique invariant having drifted
            // (defence in depth — should be a no-op once the index is
            // live).
            let row = sqlx::query(
                "WITH ins AS (\n\
                     INSERT INTO public.jobs\n\
                         (kind, params, actor_id, priority, trigger_source,\n\
                          idempotency_key, status)\n\
                     VALUES ($1, $2, $3, $4, $5, $6, 'pending')\n\
                     ON CONFLICT (idempotency_key)\n\
                         WHERE idempotency_key IS NOT NULL\n\
                         DO NOTHING\n\
                     RETURNING id\n\
                 )\n\
                 SELECT id, false AS dup FROM ins\n\
                 UNION ALL\n\
                 SELECT id, true AS dup FROM public.jobs\n\
                     WHERE idempotency_key = $6\n\
                       AND NOT EXISTS (SELECT 1 FROM ins)\n\
                 LIMIT 1",
            )
            .bind(&kind)
            .bind(sqlx::types::Json(params))
            .bind(actor_id)
            .bind(priority)
            .bind(&trigger_source)
            .bind(idempotency_key.as_deref())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Job", &kind))?;

            let id: Uuid = row.get("id");
            let dup: Option<bool> = row.try_get("dup").ok();
            if dup.unwrap_or(false) {
                Ok(EnqueueOutcome::Duplicate {
                    existing_job_id: id,
                })
            } else {
                Ok(EnqueueOutcome::Enqueued { job_id: id })
            }
        })
    }

    fn last_completed_at_by_kind<'a>(
        &'a self,
        kind: &'a str,
    ) -> BoxFuture<'a, DomainResult<Option<DateTime<Utc>>>> {
        let kind = kind.to_string();
        Box::pin(async move {
            tracing::debug!(%kind, "last_completed_at_by_kind");
            // `MAX(completed_at)` over the completed rows for this kind.
            // Ordering by completed_at (NOT id — `jobs.id` is a random
            // uuid). A kind with zero completed rows yields SQL NULL,
            // decoded as `None` — the "never ran" liveness input.
            let last: Option<DateTime<Utc>> = sqlx::query_scalar(
                "SELECT max(completed_at) \
                 FROM public.jobs \
                 WHERE kind = $1 \
                   AND status = 'completed'",
            )
            .bind(&kind)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Job", &kind))?;
            Ok(last)
        })
    }

    fn last_result_summary_by_kind<'a>(
        &'a self,
        kind: &'a str,
    ) -> BoxFuture<'a, DomainResult<Option<serde_json::Value>>> {
        let kind = kind.to_string();
        Box::pin(async move {
            tracing::debug!(%kind, "last_result_summary_by_kind");
            // Ordering by completed_at (NOT id — `jobs.id` is a random
            // uuid), mirroring `last_completed_at_by_kind`. The outer
            // `Option` is "no completed row of this kind exists yet";
            // the inner `Option` is `result_summary`'s own nullability
            // (a completed row with no summary) — `.flatten()` collapses
            // both "never ran" and "ran with nothing to report" to the
            // same `None`, which is exactly how callers already treat
            // "no cursor" (start of the walk).
            let summary: Option<Option<JsonValue>> = sqlx::query_scalar(
                "SELECT result_summary \
                 FROM public.jobs \
                 WHERE kind = $1 \
                   AND status = 'completed' \
                 ORDER BY completed_at DESC \
                 LIMIT 1",
            )
            .bind(&kind)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Job", &kind))?;
            Ok(summary.flatten())
        })
    }

    fn record_run_completion<'a>(
        &'a self,
        kind: &'a str,
        at: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<()>> {
        let kind = kind.to_string();
        Box::pin(async move {
            tracing::debug!(%kind, %at, "record_run_completion");
            // Insert a terminal liveness breadcrumb row for a recurring,
            // non-worker-dispatched run (the `verify-event-chain` CLI).
            // The boot-time `hort_event_chain_verify_overdue` gauge reads
            // the newest such row via `last_completed_at_by_kind`.
            //
            // Columns explicitly set: `kind` (migration-009 CHECK
            // includes `'verify-event-chain'`), `status='completed'`
            // (CHECK IN-list), `trigger_source='scheduled'` (a valid
            // migration-009 CHECK literal — the CronJob is the scheduled
            // driver), and `completed_at` (the run timestamp). The
            // remaining NOT NULL columns ride their schema DEFAULTs:
            // `params` → `'{}'::jsonb`, `priority` → 0 (CHECK 0..=100),
            // `attempts` → 0, `created_at`/`updated_at` → now(). No
            // `actor_id` / `idempotency_key` / scan-typed columns (all
            // nullable) — this is a pure heartbeat, not a queue row.
            sqlx::query(
                "INSERT INTO public.jobs\n\
                     (kind, status, trigger_source, completed_at)\n\
                 VALUES ($1, 'completed', 'scheduled', $2)",
            )
            .bind(&kind)
            .bind(at)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Job", &kind))?;
            Ok(())
        })
    }

    fn delete_job<'a>(&'a self, job_id: Uuid) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(%job_id, "delete_job (compensating)");
            sqlx::query("DELETE FROM public.jobs WHERE id = $1")
                .bind(job_id)
                .execute(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Job", &job_id.to_string()))?;
            Ok(())
        })
    }

    fn list_jobs<'a>(
        &'a self,
        filter: ListJobsFilter,
        limit: u32,
        cursor: Option<Uuid>,
    ) -> BoxFuture<'a, DomainResult<ListJobsPage>> {
        // Clamp limit: 0 → default 50, max 500.
        let page_size = match limit {
            0 => 51u32, // fetch one extra to detect next page
            n if n > 500 => 501u32,
            n => n + 1, // fetch one extra
        };
        Box::pin(async move {
            // Build the WHERE clause dynamically.
            // Clause order: cursor, kind, status.
            let mut conditions: Vec<String> = Vec::new();
            let mut bind_idx: u32 = 1;

            if cursor.is_some() {
                conditions.push(format!("id < ${bind_idx}"));
                bind_idx += 1;
            }
            if filter.kind.is_some() {
                conditions.push(format!("kind = ${bind_idx}"));
                bind_idx += 1;
            }
            if filter.status.is_some() {
                conditions.push(format!("status = ${bind_idx}"));
                bind_idx += 1;
            }
            let where_clause = if conditions.is_empty() {
                String::new()
            } else {
                format!("WHERE {}", conditions.join(" AND "))
            };

            let sql = format!(
                "SELECT id, kind, status, params, actor_id, priority, trigger_source, \
                     attempts, created_at, updated_at, completed_at, last_error, result_summary, \
                     artifact_id, repository_id, content_hash, format \
                 FROM public.jobs \
                 {where_clause} \
                 ORDER BY id DESC \
                 LIMIT ${bind_idx}"
            );

            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            if let Some(c) = cursor {
                q = q.bind(c);
            }
            if let Some(ref k) = filter.kind {
                q = q.bind(k);
            }
            if let Some(ref s) = filter.status {
                q = q.bind(s.as_str());
            }
            q = q.bind(page_size as i64);

            let rows = q
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Job", "list_jobs"))?;

            // The display limit is one fewer than what we fetched.
            let display_limit = (page_size - 1) as usize;
            let has_more = rows.len() > display_limit;
            let rows = if has_more {
                &rows[..display_limit]
            } else {
                &rows[..]
            };

            let mut items = Vec::with_capacity(rows.len());
            for row in rows {
                items.push(row_to_job_row(row)?);
            }

            let next_cursor = if has_more {
                items.last().map(|r| r.id)
            } else {
                None
            };

            Ok(ListJobsPage { items, next_cursor })
        })
    }

    fn get_job<'a>(&'a self, job_id: Uuid) -> BoxFuture<'a, DomainResult<Option<JobRow>>> {
        Box::pin(async move {
            let row_opt = sqlx::query(
                "SELECT id, kind, status, params, actor_id, priority, trigger_source, \
                     attempts, created_at, updated_at, completed_at, last_error, result_summary, \
                     artifact_id, repository_id, content_hash, format \
                 FROM public.jobs \
                 WHERE id = $1",
            )
            .bind(job_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Job", &job_id.to_string()))?;

            row_opt.map(|r| row_to_job_row(&r)).transpose()
        })
    }

    fn claim_pending_by_kinds<'a>(
        &'a self,
        kinds: &'a [&'a str],
        batch_size: u16,
        worker_id: &'a str,
        lock_duration: Duration,
    ) -> BoxFuture<'a, DomainResult<Vec<JobRow>>> {
        let kinds_owned: Vec<String> = kinds.iter().map(ToString::to_string).collect();
        let worker_id = worker_id.to_string();
        let interval = duration_to_pg_interval(lock_duration);
        let limit: i64 = i64::from(batch_size);
        Box::pin(async move {
            tracing::debug!(
                kinds = ?kinds_owned,
                batch_size,
                worker_id = %worker_id,
                "claim_pending_by_kinds",
            );
            // Two-CTE claim across multiple kinds:
            //   1. SELECT pending rows of any registered kind whose
            //      lock has expired or was never set, ordered by
            //      priority DESC then created_at ASC, SKIP LOCKED.
            //   2. UPDATE the picked ids to running + bump attempts,
            //      RETURNING the generic cross-kind column set.
            let rows = sqlx::query(CLAIM_PENDING_BY_KINDS_SQL)
                .bind(&kinds_owned)
                .bind(limit)
                .bind(&worker_id)
                .bind(interval)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Job", "claim_pending_by_kinds"))?;
            // Per-row projection, NOT `collect::<DomainResult<_>>()?`.
            //
            // The `?` form propagated the FIRST mapping error out of the
            // function *after* the claiming UPDATE had already committed:
            // every row in the batch was `running`, none was returned to
            // the caller, and nothing ever moved them back — the claim
            // predicate requires `status = 'pending'`. One unmappable row
            // therefore stranded up to `batch_size` healthy rows
            // (invariant: a claimed-but-not-dispatched row is never
            // permanently lost). `requeue_abandoned` would now recover
            // them a lease plus a grace later, but only for the kinds in
            // the requeue allow-list and only after half an hour at the
            // defaults; resolving the unmappable row terminally right
            // here keeps the rest of the batch moving on this tick. The shape used to
            // be production-reachable: `"scan"` was in
            // `ADMIN_INVOKABLE_TASK_KINDS`, so the admin task-invoke
            // path's `enqueue_task` wrote a `kind='scan'` row with the
            // scan-typed columns NULL, which `decide_kind_fields` rejects.
            // That source is now closed at the apply side (no admin
            // route, and the kind is off the allow-list) — bare-`scan`
            // rows lacking the scan-typed columns are legacy/poison only
            // now, reachable solely via direct SQL, an older deployment's
            // leftover row, or a future kind whose typed columns go
            // missing; the `jobs` table still has no CHECK preventing the
            // shape, so this per-row projection stays defence-in-depth.
            //
            // Now each row is projected independently: mappable rows are
            // returned and dispatched; an unmappable row is resolved
            // TERMINALLY (`mark_failed`, carrying the projection error as
            // `last_error`) plus an ERROR log and a metric. Terminal
            // rather than revert-to-`pending` on purpose — an unmappable
            // row is unmappable on every subsequent claim too, so
            // re-queueing it would swap silent loss for a hot loop that
            // burns a batch slot every poll.
            let mut jobs: Vec<JobRow> = Vec::with_capacity(rows.len());
            let mut unmappable: Vec<(Uuid, String)> = Vec::new();
            for row in &rows {
                match row_to_job_row(row) {
                    Ok(job) => jobs.push(job),
                    Err(e) => match row.try_get::<Uuid, _>("id") {
                        Ok(id) => unmappable.push((id, e.to_string())),
                        Err(id_err) => {
                            // The `id` column itself is unreadable, so the
                            // row cannot even be addressed for a terminal
                            // transition. Pinned as unreachable by
                            // `claim_pending_by_kinds_sql_*` (the
                            // RETURNING clause always projects `id`);
                            // logged rather than silently dropped.
                            tracing::error!(
                                error = %e,
                                id_error = %id_err,
                                "claim_pending_by_kinds: claimed row is unmappable AND its id is \
                                 unreadable; the row stays 'running' and cannot be re-claimed"
                            );
                        }
                    },
                }
            }
            for (id, reason) in unmappable {
                tracing::error!(
                    job_id = %id,
                    reason = %reason,
                    "claim_pending_by_kinds: claimed row failed projection; marking it failed so \
                     it is not stranded in 'running' (the rest of the batch is dispatched)"
                );
                metrics::counter!(METRIC_CLAIM_UNMAPPABLE).increment(1);
                if let Err(e) = JobsRepository::mark_failed(self, id, &reason).await {
                    tracing::error!(
                        job_id = %id,
                        error = %e,
                        "claim_pending_by_kinds: marking the unmappable row failed did not persist",
                    );
                }
            }
            sort_claimed_jobs(&mut jobs);
            Ok(jobs)
        })
    }

    fn renew_lease<'a>(
        &'a self,
        job_id: Uuid,
        worker_id: &'a str,
        lock_duration: Duration,
    ) -> BoxFuture<'a, DomainResult<bool>> {
        let worker_id = worker_id.to_string();
        let interval = duration_to_pg_interval(lock_duration);
        Box::pin(async move {
            tracing::debug!(%job_id, worker_id = %worker_id, "renew_lease");
            let res = sqlx::query(RENEW_LEASE_SQL)
                .bind(job_id)
                .bind(&worker_id)
                .bind(interval)
                .execute(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Job", "renew_lease"))?;
            Ok(res.rows_affected() == 1)
        })
    }

    fn requeue_abandoned<'a>(
        &'a self,
        kinds: &'a [&'a str],
        grace: Duration,
        attempt_cap: u32,
        batch_size: u16,
    ) -> BoxFuture<'a, DomainResult<Vec<RequeuedJob>>> {
        let kinds_owned: Vec<String> = kinds.iter().map(ToString::to_string).collect();
        let grace_interval = duration_to_pg_interval(grace);
        let backoff_interval = duration_to_pg_interval(REQUEUE_BACKOFF);
        let cap = i64::from(attempt_cap);
        let limit = i64::from(batch_size);
        Box::pin(async move {
            if kinds_owned.is_empty() {
                return Ok(Vec::new());
            }
            tracing::debug!(
                kinds = ?kinds_owned,
                grace_secs = grace.as_secs(),
                attempt_cap,
                batch_size,
                "requeue_abandoned",
            );
            let rows = sqlx::query(REQUEUE_ABANDONED_SQL)
                .bind(&kinds_owned)
                .bind(grace_interval)
                .bind(limit)
                .bind(cap)
                .bind(backoff_interval)
                .bind(REQUEUE_LAST_ERROR)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Job", "requeue_abandoned"))?;
            rows.iter()
                .map(|row| {
                    let status: String = row.try_get("status").map_err(|e| invariant(&e))?;
                    let attempts: i32 = row.try_get("attempts").map_err(|e| invariant(&e))?;
                    Ok(RequeuedJob {
                        id: row.try_get("id").map_err(|e| invariant(&e))?,
                        kind: row.try_get("kind").map_err(|e| invariant(&e))?,
                        attempts: u32::try_from(attempts).unwrap_or(u32::MAX),
                        outcome: match status.as_str() {
                            "pending" => RequeueOutcome::Requeued,
                            "failed" => RequeueOutcome::RetriesExhausted,
                            other => {
                                return Err(DomainError::Invariant(format!(
                                    "requeue_abandoned returned status {other:?}; the CASE \
                                     produces only 'pending' or 'failed'"
                                )))
                            }
                        },
                    })
                })
                .collect()
        })
    }

    fn eligible_pending_by_kind(&self) -> BoxFuture<'_, DomainResult<Vec<PendingKindBacklog>>> {
        Box::pin(async move {
            // Mirrors the claim query's eligibility predicates minus the
            // `kind = ANY(...)` filter — see the port doc.
            let rows = sqlx::query(
                "SELECT kind, count(*) AS n, min(created_at) AS oldest \
                 FROM public.jobs \
                 WHERE status = 'pending' \
                   AND (locked_until IS NULL OR locked_until < now()) \
                 GROUP BY kind",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Job", "eligible_pending_by_kind"))?;
            rows.iter()
                .map(|row| {
                    Ok(PendingKindBacklog {
                        kind: row.try_get("kind").map_err(|e| invariant(&e))?,
                        count: row.try_get("n").map_err(|e| invariant(&e))?,
                        oldest_created_at: row.try_get("oldest").map_err(|e| invariant(&e))?,
                    })
                })
                .collect()
        })
    }

    // ----------------------------------------------------------------
    // cascade-specific entry points
    // ----------------------------------------------------------------

    fn enqueue_prefetch_batch<'a>(
        &'a self,
        rows: &'a [hort_domain::ports::jobs_repository::PrefetchEnqueueRow],
    ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>> {
        // Clone the inputs into owned values so the returned future is
        // `'static` w.r.t. its borrows on the slice. `sqlx::query` binds
        // are `&` to the bound values so the owned `Vec`s must outlive
        // the await.
        let owned: Vec<hort_domain::ports::jobs_repository::PrefetchEnqueueRow> = rows.to_vec();
        Box::pin(async move {
            if owned.is_empty() {
                return Ok(Vec::new());
            }
            // The L3 partial unique index is per-`kind`; do one
            // batched INSERT per distinct kind so the ON CONFLICT
            // resolution matches the correct partial-unique index
            // (`jobs_prefetch_unique` vs `jobs_prefetch_dependencies_unique`).
            use std::collections::BTreeMap;
            let mut by_kind: BTreeMap<
                String,
                Vec<&hort_domain::ports::jobs_repository::PrefetchEnqueueRow>,
            > = BTreeMap::new();
            for r in &owned {
                by_kind.entry(r.kind.clone()).or_default().push(r);
            }

            let mut inserted: Vec<Uuid> = Vec::new();
            for (kind, kind_rows) in by_kind {
                // Build a multi-row INSERT. Bind parameters are
                // numbered $1, $2, …; each row contributes 5 binds
                // (kind, params, priority, trigger_source, target_key).
                let mut placeholders: Vec<String> = Vec::with_capacity(kind_rows.len());
                for i in 0..kind_rows.len() {
                    let base = i * 5;
                    placeholders.push(format!(
                        "(${},${},${},${},${},'pending')",
                        base + 1,
                        base + 2,
                        base + 3,
                        base + 4,
                        base + 5,
                    ));
                }
                // The ON CONFLICT predicate MUST match the WHERE
                // clause of the partial unique index for the target
                // kind exactly — PostgreSQL resolves
                // `ON CONFLICT (col) WHERE pred` by looking for a
                // partial unique index whose WHERE is *implied by*
                // the supplied `pred`. Two disjoint per-kind indexes
                // (`jobs_prefetch_unique` for kind = 'prefetch';
                // `jobs_prefetch_dependencies_unique` for kind =
                // 'prefetch-dependencies') means a per-kind ON CONFLICT
                // predicate, not a single combined `kind IN (...)` one
                // (which would not match either index exactly and
                // would surface as `there is no unique or exclusion
                // constraint matching the ON CONFLICT specification`).
                let on_conflict_kind_pred = match kind.as_str() {
                    "prefetch" => "kind = 'prefetch'",
                    "prefetch-dependencies" => "kind = 'prefetch-dependencies'",
                    other => {
                        return Err(DomainError::Invariant(format!(
                            "enqueue_prefetch_batch: unsupported kind {other:?} (only \
                             'prefetch' and 'prefetch-dependencies' are valid)"
                        )));
                    }
                };
                let sql = format!(
                    "INSERT INTO public.jobs \
                       (kind, params, priority, trigger_source, target_key, status) \
                     VALUES {placeholders} \
                     ON CONFLICT (target_key) \
                       WHERE {on_conflict_kind_pred} \
                         AND target_key IS NOT NULL \
                         AND status IN ('pending','running') \
                     DO NOTHING \
                     RETURNING id",
                    placeholders = placeholders.join(", "),
                );
                let mut q = sqlx::query_scalar::<_, Uuid>(sqlx::AssertSqlSafe(sql));
                for r in &kind_rows {
                    q = q
                        .bind(&r.kind)
                        .bind(sqlx::types::Json(r.params.clone()))
                        .bind(r.priority)
                        .bind(&r.trigger_source)
                        .bind(&r.target_key);
                }
                let ids: Vec<Uuid> = q
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| map_sqlx_error(&e, "Job", "enqueue_prefetch_batch"))?;
                inserted.extend(ids);
            }
            tracing::info!(
                attempted = owned.len(),
                inserted = inserted.len(),
                deduped = owned.len() - inserted.len(),
                "enqueue_prefetch_batch",
            );
            Ok(inserted)
        })
    }

    fn enqueue_idempotent_batch<'a>(
        &'a self,
        rows: &'a [hort_domain::ports::jobs_repository::IdempotentEnqueueRow],
    ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>> {
        // Same owning rationale as `enqueue_prefetch_batch`: `sqlx::query`
        // binds borrow the bound values, so the owned `Vec` must outlive
        // the await.
        let owned: Vec<hort_domain::ports::jobs_repository::IdempotentEnqueueRow> = rows.to_vec();
        Box::pin(async move {
            if owned.is_empty() {
                return Ok(Vec::new());
            }
            // One statement for the whole cohort, regardless of kind:
            // unlike the `prefetch%`-scoped `target_key` indexes,
            // `jobs_idempotency_key_uq` is a single index over every
            // non-NULL key, so there is no per-kind partitioning to do
            // and the ON CONFLICT predicate is the index's own WHERE.
            //
            // Each row contributes 5 binds (kind, params, priority,
            // trigger_source, idempotency_key); `status` is the literal
            // 'pending' and `actor_id` is left to its NULL default (see
            // the port doc for why these rows carry no actor).
            let mut placeholders: Vec<String> = Vec::with_capacity(owned.len());
            for i in 0..owned.len() {
                let base = i * 5;
                placeholders.push(format!(
                    "(${},${},${},${},${},'pending')",
                    base + 1,
                    base + 2,
                    base + 3,
                    base + 4,
                    base + 5,
                ));
            }
            let sql = format!(
                "INSERT INTO public.jobs \
                   (kind, params, priority, trigger_source, idempotency_key, status) \
                 VALUES {placeholders} \
                 ON CONFLICT (idempotency_key) \
                   WHERE idempotency_key IS NOT NULL \
                 DO NOTHING \
                 RETURNING id",
                placeholders = placeholders.join(", "),
            );
            let mut q = sqlx::query_scalar::<_, Uuid>(sqlx::AssertSqlSafe(sql));
            for r in &owned {
                q = q
                    .bind(&r.kind)
                    .bind(sqlx::types::Json(r.params.clone()))
                    .bind(r.priority)
                    .bind(&r.trigger_source)
                    .bind(r.idempotency_key.as_str());
            }
            let inserted: Vec<Uuid> = q
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Job", "enqueue_idempotent_batch"))?;
            tracing::info!(
                attempted = owned.len(),
                inserted = inserted.len(),
                deduped = owned.len() - inserted.len(),
                "enqueue_idempotent_batch",
            );
            Ok(inserted)
        })
    }

    fn delete_terminal_prefetch_rows_older_than<'a>(
        &'a self,
        horizon: Duration,
    ) -> BoxFuture<'a, DomainResult<u64>> {
        let interval = duration_to_pg_interval(horizon);
        Box::pin(async move {
            tracing::debug!(?horizon, "delete_terminal_prefetch_rows_older_than");
            // `oci-index-child-ingest` rides this sweep rather than getting
            // its own: it is the same class of work as the cascade — a
            // high-churn, best-effort, per-content unit of pull-through
            // ingest whose terminal row holds no durable state. `prefetch-tick`
            // is carved back out for the opposite reason. See the port doc
            // and the SQL constant for both.
            let res = sqlx::query(DELETE_TERMINAL_PREFETCH_ROWS_SQL)
                .bind(interval)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "Job", "delete_terminal_prefetch_rows_older_than")
                })?;
            Ok(res.rows_affected())
        })
    }

    fn delete_terminal_scan_rows_older_than<'a>(
        &'a self,
        horizon: Duration,
    ) -> BoxFuture<'a, DomainResult<u64>> {
        let interval = duration_to_pg_interval(horizon);
        Box::pin(async move {
            tracing::debug!(?horizon, "delete_terminal_scan_rows_older_than");
            let res = sqlx::query(
                "DELETE FROM public.jobs \
                  WHERE kind = 'scan' \
                    AND status IN ('completed', 'failed') \
                    AND updated_at < now() - $1::interval",
            )
            .bind(interval)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Job", "delete_terminal_scan_rows_older_than"))?;
            Ok(res.rows_affected())
        })
    }

    fn delete_terminal_other_kind_rows_older_than<'a>(
        &'a self,
        horizon: Duration,
    ) -> BoxFuture<'a, DomainResult<u64>> {
        let interval = duration_to_pg_interval(horizon);
        Box::pin(async move {
            tracing::debug!(?horizon, "delete_terminal_other_kind_rows_older_than");
            let res = sqlx::query(DELETE_TERMINAL_OTHER_KIND_ROWS_SQL)
                .bind(interval)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "Job", "delete_terminal_other_kind_rows_older_than")
                })?;
            Ok(res.rows_affected())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `duration_to_pg_interval` round-trips a typical
    /// 15-minute lock window.
    #[test]
    fn duration_to_pg_interval_15_minutes() {
        let d = Duration::from_secs(900);
        let i = duration_to_pg_interval(d);
        assert_eq!(i.months, 0);
        assert_eq!(i.days, 0);
        assert_eq!(i.microseconds, 900_000_000);
    }

    /// `duration_to_pg_interval` clamps absurd values rather than
    /// panicking. The clamp boundary is `i64::MAX` microseconds —
    /// pragmatically infinite (~292,000 years).
    #[test]
    fn duration_to_pg_interval_clamps_overflow() {
        let d = Duration::from_secs(u64::MAX / 2);
        let i = duration_to_pg_interval(d);
        assert_eq!(i.microseconds, i64::MAX);
    }

    // ---- abandoned-lease sweep SQL -----------------------------------------

    /// The sweep must never widen past `status = 'running'`.
    ///
    /// A predicate that also matched `pending` would re-drive rows the
    /// claim already handles correctly; one that matched a terminal row
    /// would resurrect finished work. The `\n\` continuation hazard the
    /// `claim_pending_by_kinds_sql_has_no_token_mashing` test documents
    /// applies verbatim here, so the token-separation check comes along
    /// with it.
    #[test]
    fn requeue_abandoned_sql_targets_only_running_rows_with_a_real_lease() {
        let sql = REQUEUE_ABANDONED_SQL;
        for token in [
            "WHERE status = 'running'",
            "AND kind = ANY($1::text[])",
            "AND locked_until IS NOT NULL",
            "AND locked_until < now() - $2::interval",
            "FOR UPDATE SKIP LOCKED",
            "ORDER BY locked_until ASC, id ASC",
        ] {
            assert!(
                sql.contains(token),
                "requeue_abandoned SQL is missing the token-separated fragment {token:?}; \
                 a bare `\\` line continuation eats the newline AND the indent and mashes \
                 adjacent tokens together"
            );
        }
        assert!(
            !sql.contains("'pending'\n"),
            "the sweep selects 'running' rows only — the claim already handles 'pending'"
        );
        assert!(
            !sql.contains("DELETE"),
            "an abandoned row is requeued, never deleted: it may be genuinely running, and \
             its completion is an unconditional UPDATE by id that must still find a row"
        );
    }

    /// The attempt cap is enforced inside the sweep statement.
    ///
    /// The sweep is the only code that runs for a row whose handler
    /// never returned, so a cap applied anywhere else (the scan
    /// orchestrator's `attempts >= max_attempts`, the dispatcher's
    /// `TaskOutcome::Failed` arms) is unreachable for exactly the rows
    /// that need it. A repeatedly-crashing task must terminate.
    #[test]
    fn requeue_abandoned_sql_caps_retries_and_leaves_attempts_alone() {
        let sql = REQUEUE_ABANDONED_SQL;
        assert!(
            sql.contains("CASE WHEN j.attempts >= $4 THEN 'failed' ELSE 'pending' END"),
            "the retry budget has to be spent here or a crash loop is re-driven forever"
        );
        assert!(
            !sql.contains("attempts = attempts + 1") && !sql.contains("attempts = j.attempts"),
            "the CLAIM increments `attempts`; a sweep that also incremented would charge a \
             row twice for one execution attempt"
        );
        assert!(
            sql.contains("locked_by = NULL"),
            "the dead worker's claim must be released or the row reads as still held"
        );
    }

    /// The renewal is fenced on both the holder and the status.
    ///
    /// `locked_by = $2` stops a worker whose row was swept from
    /// extending the sibling's lease, and makes the zero-rows result the
    /// signal that it lost the row. `status = 'running'` stops a renewal
    /// that races the outcome write from leaving a terminal row with a
    /// future lease.
    #[test]
    fn renew_lease_sql_is_fenced_on_holder_and_status() {
        let sql = RENEW_LEASE_SQL;
        for token in [
            "WHERE id = $1",
            "AND locked_by = $2",
            "AND status = 'running'",
            "locked_until = now() + $3",
        ] {
            assert!(sql.contains(token), "renew_lease SQL missing {token:?}");
        }
        let (set_clause, _predicate) = sql
            .split_once("WHERE")
            .expect("renew_lease SQL has a WHERE clause");
        assert!(
            !set_clause.contains("status"),
            "renewal extends a lease and nothing else; assigning `status` here would let a \
             renewal tick move a row's lifecycle state behind the handler's back"
        );
        assert!(
            !set_clause.contains("attempts"),
            "a renewal is not an execution attempt — only the claim charges the budget"
        );
    }

    /// Regression guard for the `claim_pending_by_kinds` SQL. A prior
    /// version used bare `\` line continuations (no leading `\n`),
    /// which eat both the newline AND the following indent — producing
    /// strings like `public.jobsWHERE status = 'pending'AND kind =
    /// ANY(...)`. The worker's poll loop then failed every 5s with
    /// `syntax error at or near "="`. This test pins the conjoined
    /// token pairs the bug produced so any future "compact this query"
    /// edit that re-introduces it fails the build instead of the
    /// running worker.
    #[test]
    fn claim_pending_by_kinds_sql_has_no_token_mashing() {
        let sql = CLAIM_PENDING_BY_KINDS_SQL;

        // Positive shape: keyword pairs MUST be separated by whitespace.
        // Each substring below was (or, for the reserved-oldest-slot CTEs,
        // would be) a token-mashing site if a `\n` were dropped.
        let must_contain = [
            "FROM public.jobs",
            "public.jobs\n",
            "'pending'\n",
            "ANY($1::text[])\n",
            "now())\n",
            "LIMIT LEAST($2, 1)\n",
            "LIMIT GREATEST($2 - 1, 0)\n",
            "FROM oldest\n",
            "FROM ranked\n",
            "NOT IN (SELECT id FROM oldest)\n",
            "UPDATE public.jobs SET\n",
            "now()\n",
            "FROM claimed)\n",
        ];
        for pat in &must_contain {
            assert!(
                sql.contains(pat),
                "claim_pending_by_kinds SQL missing expected token-separated \
                 pattern `{pat}` — likely a line-continuation regression. \
                 Full SQL:\n{sql}"
            );
        }

        // Negative shape: explicit forbidden conjoined pairs that the
        // bare-`\` bug produced (or would produce in the new CTEs).
        // Listing them as substrings guards against any future regression
        // that drops a `\n` before a continuation.
        let must_not_contain = [
            "jobsWHERE",
            "'pending'AND",
            "ANY($1::text[])AND",
            "now())ORDER",
            "FOR UPDATE SKIP LOCKEDLIMIT",
            "now()WHERE",
            "oldest)ORDER",
        ];
        for pat in &must_not_contain {
            assert!(
                !sql.contains(pat),
                "claim_pending_by_kinds SQL contains conjoined-token \
                 pattern `{pat}` — a `\\n` is missing on a line \
                 continuation. Full SQL:\n{sql}"
            );
        }
    }

    /// Regression guard for the reserved-oldest-slot fairness shape: one
    /// slot per poll MUST be reserved for the single oldest eligible row
    /// across kinds, priority-blind, and it MUST be excluded from the
    /// priority-ordered slots so the same row is never double-claimed.
    /// A prior bug class (see the token-mashing guard above) proved that
    /// this query's shape is easy to silently corrupt during an edit; this
    /// test pins the fairness-specific invariants the token-mashing guard
    /// does not cover.
    #[test]
    fn claim_pending_by_kinds_sql_reserves_one_priority_blind_oldest_slot() {
        let sql = CLAIM_PENDING_BY_KINDS_SQL;

        // The reserved slot's ordering must NOT reference priority — it is
        // the single globally oldest row regardless of priority.
        let oldest_cte = sql
            .split_once("ranked AS (")
            .map(|(before, _)| before)
            .expect("CLAIM_PENDING_BY_KINDS_SQL must contain a `ranked` CTE");
        assert!(
            oldest_cte.contains("ORDER BY created_at ASC, id ASC"),
            "the `oldest` CTE must order by created_at alone (priority-blind). \
             Full `oldest` CTE:\n{oldest_cte}"
        );
        assert!(
            !oldest_cte.contains("priority"),
            "the `oldest` CTE must not reference priority — it reserves a slot \
             for the oldest row REGARDLESS of priority. Full `oldest` CTE:\n{oldest_cte}"
        );

        // The ranked (priority-ordered) slots must exclude whatever the
        // oldest CTE already picked, and must keep the pre-existing
        // priority-ordered contract for the remaining slots.
        assert!(
            sql.contains("ORDER BY priority DESC, created_at ASC"),
            "the `ranked` CTE must keep the pre-existing priority DESC, \
             created_at ASC order for the non-reserved slots. Full SQL:\n{sql}"
        );

        // Both CTEs preserve FOR UPDATE SKIP LOCKED semantics.
        assert_eq!(
            sql.matches("FOR UPDATE SKIP LOCKED").count(),
            2,
            "both the `oldest` and `ranked` CTEs must claim with FOR UPDATE \
             SKIP LOCKED. Full SQL:\n{sql}"
        );

        // `oldest` is referenced twice (by `ranked`'s exclusion and by
        // `claimed`'s union) — it must be MATERIALIZED so the FOR UPDATE
        // SKIP LOCKED select runs once, not once per reference.
        assert!(
            sql.contains("WITH oldest AS MATERIALIZED ("),
            "the `oldest` CTE must be explicitly MATERIALIZED — it is \
             referenced twice, and relying on the default multiply-referenced \
             materialization is exactly the kind of implicit contract this \
             file pins explicitly. Full SQL:\n{sql}"
        );
    }

    // ---- DELETE_TERMINAL_OTHER_KIND_ROWS_SQL ------------------------------
    //
    // DB-free pins on the generic sweep's query. Each assertion below
    // stands for a property whose loss is silent: the query still runs,
    // still reports a plausible deleted count, and quietly takes out
    // state some other reader depends on.

    /// The kind predicate must stay the exact textual complement of the
    /// two kind-specific sweeps. Overlap would put two horizon constants
    /// in force for the same rows and let the shorter one silently win,
    /// so the kind would age out on a horizon neither of its sweeps
    /// documents — invisible today only because all three constants read
    /// 7 days.
    #[test]
    fn delete_terminal_other_kind_rows_sql_excludes_the_kind_specific_sweeps() {
        let sql = DELETE_TERMINAL_OTHER_KIND_ROWS_SQL;
        assert!(
            sql.contains("kind NOT LIKE 'prefetch%'"),
            "the cascade sweep's `kind LIKE 'prefetch%'` must be excluded. \
             Full SQL:\n{sql}"
        );
        assert!(
            sql.contains("kind NOT IN ('scan', 'oci-index-child-ingest')"),
            "the scan sweep's `kind = 'scan'` and the cascade sweep's \
             `oci-index-child-ingest` must be excluded. Full SQL:\n{sql}"
        );
    }

    /// The `prefetch%` prefix is **partitioned** between the two sweeps,
    /// not shared and not dropped: the cascade sweep carves
    /// `prefetch-tick` out, the generic sweep takes it back. Both halves
    /// are load-bearing and they fail in opposite directions — lose the
    /// carve-out and the cascade sweep (which has no keep-newest clause)
    /// deletes the rotation's keyset cursor, restarting the walk from the
    /// beginning; lose the readmission and the kind is swept by nothing
    /// at all and its terminal rows accumulate forever. Neither failure
    /// is visible in a passing run of either sweep, which is why the pin
    /// reads both strings in one test.
    #[test]
    fn the_two_sweeps_partition_the_prefetch_prefix() {
        let cascade = DELETE_TERMINAL_PREFETCH_ROWS_SQL;
        let generic = DELETE_TERMINAL_OTHER_KIND_ROWS_SQL;
        assert!(
            cascade.contains("kind LIKE 'prefetch%' AND kind <> 'prefetch-tick'"),
            "the cascade sweep must carve `prefetch-tick` out of the prefix match — \
             its newest `completed` row carries the prefetch rotation's keyset cursor \
             and this sweep has no keep-newest clause. Full SQL:\n{cascade}"
        );
        assert!(
            generic.contains("kind NOT LIKE 'prefetch%' OR kind = 'prefetch-tick'"),
            "the generic sweep must readmit `prefetch-tick`, or the kind is swept by \
             nothing and its terminal rows accumulate forever. Full SQL:\n{generic}"
        );
        assert!(
            cascade.contains("kind = 'oci-index-child-ingest'")
                && generic.contains("kind NOT IN ('scan', 'oci-index-child-ingest')"),
            "`oci-index-child-ingest` stays wholly on the cascade side — it is the \
             counter-example to the carve-out: high-churn, stateless terminal row. \
             Cascade SQL:\n{cascade}\nGeneric SQL:\n{generic}"
        );
    }

    /// Counter-assertion for the partition pin above: the cascade
    /// predicate really is a `prefetch%` prefix match plus the one
    /// `oci-index-child-ingest` literal, restricted to terminal rows on
    /// the same `$1::interval` horizon as its siblings. A rewrite that
    /// dropped the prefix match entirely would leave
    /// `the_two_sweeps_partition_the_prefetch_prefix` asserting about a
    /// predicate that no longer selects the cascade.
    #[test]
    fn delete_terminal_prefetch_rows_sql_is_the_cascade_predicate() {
        let sql = DELETE_TERMINAL_PREFETCH_ROWS_SQL;
        assert!(
            sql.starts_with("DELETE FROM public.jobs\n"),
            "Full SQL:\n{sql}"
        );
        assert_eq!(
            sql.matches("kind LIKE 'prefetch%'").count(),
            1,
            "exactly one prefix match, so a future `prefetch%` kind inherits this sweep \
             without an edit. Full SQL:\n{sql}"
        );
        assert!(
            sql.contains("status IN ('completed', 'failed')"),
            "`pending` / `running` rows are never swept. Full SQL:\n{sql}"
        );
        assert!(
            sql.contains("updated_at < now() - $1::interval"),
            "the horizon is the bound parameter, not a literal. Full SQL:\n{sql}"
        );
        assert!(
            !sql.contains("newest_completed_at"),
            "this sweep deliberately has NO keep-newest clause — adding one here would \
             put the rule in two statements. `prefetch-tick` is carved out instead. \
             Full SQL:\n{sql}"
        );
    }

    /// Two rows per kind are retained, not one, and the `completed` half
    /// is the one a "keep the newest terminal row" reading would drop.
    /// Dropping it makes `last_completed_at_by_kind` answer `None` —
    /// "never ran" — for any kind whose newest terminal row is a failure,
    /// which is exactly the state a stopped-and-failing scheduled task is
    /// in when its gauge most needs to be right.
    #[test]
    fn delete_terminal_other_kind_rows_sql_retains_both_state_rows_per_kind() {
        let sql = DELETE_TERMINAL_OTHER_KIND_ROWS_SQL;
        assert!(
            sql.contains("max(completed_at) FILTER (WHERE status = 'completed')"),
            "the newest-completion anchor must mirror `last_completed_at_by_kind`'s \
             `max(completed_at) … WHERE status = 'completed'` exactly. Full SQL:\n{sql}"
        );
        assert!(
            sql.contains("j.completed_at IS NOT DISTINCT FROM l.newest_completed_at"),
            "the newest `completed` row per kind must be retained, and by equality \
             (not a ranking window) so a `completed_at` tie retains both tied rows \
             rather than guessing which one the reader lands on. Full SQL:\n{sql}"
        );
        assert!(
            sql.contains("max(created_at) AS newest_created_at"),
            "the newest-terminal anchor must be `created_at`, matching the \
             `ORDER BY created_at DESC LIMIT 1` reader. Full SQL:\n{sql}"
        );
        assert!(
            sql.contains("j.created_at <> l.newest_created_at"),
            "the newest terminal row per kind must be retained. Full SQL:\n{sql}"
        );
    }

    /// The `live` CTE aggregates over ALL terminal rows of a kind, not
    /// only the aged ones: the horizon belongs in the DELETE. Moving it
    /// into the CTE would retain "the newest row that happened to be
    /// old", a different row that then never ages out.
    #[test]
    fn delete_terminal_other_kind_rows_sql_applies_the_horizon_only_in_the_delete() {
        let sql = DELETE_TERMINAL_OTHER_KIND_ROWS_SQL;
        assert_eq!(
            sql.matches("updated_at < now() - $1::interval").count(),
            1,
            "the horizon predicate appears exactly once, in the DELETE. Full SQL:\n{sql}"
        );
        let cte = sql
            .split_once(")\nDELETE FROM")
            .map(|(before, _)| before)
            .expect("the SQL must be a `live` CTE followed by the DELETE");
        assert!(
            !cte.contains("$1"),
            "the `live` CTE must not read the horizon — it anchors on the newest \
             rows of the kind overall. Full CTE:\n{cte}"
        );
        assert_eq!(
            sql.matches("status IN ('completed', 'failed')").count(),
            2,
            "both the CTE and the DELETE restrict to terminal rows; `pending` / \
             `running` rows are never swept and never anchor. Full SQL:\n{sql}"
        );
    }

    /// Same `\n\`-continuation hazard `claim_pending_by_kinds_sql_has_no_token_mashing`
    /// pins: a continuation that loses its explicit `\n` eats both the
    /// newline and the following indent, conjoining adjacent SQL tokens
    /// into a syntax error at runtime rather than at build time.
    #[test]
    fn delete_terminal_other_kind_rows_sql_has_no_token_mashing() {
        let sql = DELETE_TERMINAL_OTHER_KIND_ROWS_SQL;
        for must_contain in [
            "WITH live AS (\n",
            "FROM public.jobs\n",
            "GROUP BY kind\n",
            "DELETE FROM public.jobs j\n",
            "USING live l\n",
        ] {
            assert!(
                sql.contains(must_contain),
                "expected {must_contain:?} with its newline intact. Full SQL:\n{sql}"
            );
        }
        for mashed in [
            "public.jobsWHERE",
            "'failed')AND",
            "GROUP BY kindDELETE",
            "public.jobs jUSING",
            "live lWHERE",
            "AS newest_created_atFROM",
        ] {
            assert!(
                !sql.contains(mashed),
                "token mashing detected ({mashed:?}) — a `\\n\\` continuation lost its \
                 explicit newline. Full SQL:\n{sql}"
            );
        }
    }

    /// Regression guard for the bug that produced
    /// `scan job <id>: artifact_id is NULL in claim_pending_by_kinds result`
    /// at runtime: `CLAIM_PENDING_BY_KINDS_SQL`'s `RETURNING` clause must
    /// include the four scan-typed columns. Without them, `row_to_job_row`
    /// decodes `kind='scan'` rows with all four set to `None` and the
    /// `ScanTaskHandler` fails every claim.
    ///
    /// The legacy single-kind `claim_scan_jobs` query has the same
    /// constraint, encoded via `RETURNING_COLS`; the multi-kind query
    /// must match.
    #[test]
    fn claim_pending_by_kinds_sql_returning_includes_scan_typed_columns() {
        let sql = CLAIM_PENDING_BY_KINDS_SQL;
        // Locate the RETURNING clause so we only inspect the projected
        // column list, not the rest of the SQL (which legitimately
        // references these columns in CTE / WHERE constructs in other
        // queries on the same file).
        let returning = sql
            .split_once("RETURNING")
            .map(|(_, after)| after)
            .expect("CLAIM_PENDING_BY_KINDS_SQL must contain a RETURNING clause");
        for col in ["artifact_id", "repository_id", "content_hash", "format"] {
            assert!(
                returning.contains(col),
                "claim_pending_by_kinds RETURNING is missing scan-typed column \
                 `{col}` — kind='scan' rows will decode with this field as None \
                 and the worker will reject every scan with \
                 `<col> is NULL in claim_pending_by_kinds result`. \
                 Full RETURNING clause:\nRETURNING{returning}"
            );
        }
    }

    /// `duration_to_pg_interval` of zero is zero microseconds.
    #[test]
    fn duration_to_pg_interval_zero() {
        let i = duration_to_pg_interval(Duration::from_secs(0));
        assert_eq!(i.microseconds, 0);
    }

    // ---- decide_kind_fields ----------------------------------------------
    //
    // The adapter projects raw `Option<...>` columns into `KindFields` —
    // a sum type that makes "this is a scan row and all four typed
    // columns are present" structurally distinct from "this is some
    // other kind with no typed projection". A `kind='scan'` row with
    // any of the four columns missing is a RETURNING-clause bug, not a
    // legitimate state; we refuse to construct a half-populated row.

    /// Valid SHA-256 hex string for fabricating a [`ContentHash`] in tests.
    const TEST_HASH_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn decide_kind_fields_scan_with_all_columns_returns_scan_variant() {
        let job_id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let content_hash = ContentHash::from_str(TEST_HASH_HEX).unwrap();
        let format = "npm".to_string();

        let kf = decide_kind_fields(
            job_id,
            "scan",
            Some(artifact_id),
            Some(repository_id),
            Some(content_hash.clone()),
            Some(format.clone()),
        )
        .expect("decide_kind_fields should succeed on a fully-populated scan row");

        match kf {
            KindFields::Scan(s) => {
                assert_eq!(s.artifact_id, artifact_id);
                assert_eq!(s.repository_id, repository_id);
                assert_eq!(s.content_hash, content_hash);
                assert_eq!(s.format, format);
            }
            KindFields::Other => panic!("expected KindFields::Scan, got Other"),
        }
    }

    #[test]
    fn decide_kind_fields_scan_with_missing_artifact_id_is_invariant() {
        let err = decide_kind_fields(
            Uuid::new_v4(),
            "scan",
            None, // <-- the bug
            Some(Uuid::new_v4()),
            Some(ContentHash::from_str(TEST_HASH_HEX).unwrap()),
            Some("npm".into()),
        )
        .expect_err("decide_kind_fields must refuse a scan row with missing artifact_id");

        match err {
            DomainError::Invariant(msg) => {
                assert!(
                    msg.contains("artifact_id") && msg.contains("scan"),
                    "Invariant message should name the offending column and kind \
                     so the operator can locate the RETURNING-clause bug: got {msg:?}"
                );
            }
            other => panic!("expected DomainError::Invariant, got {other:?}"),
        }
    }

    #[test]
    fn decide_kind_fields_non_scan_kind_returns_other() {
        let kf = decide_kind_fields(Uuid::new_v4(), "staging-sweep", None, None, None, None)
            .expect("decide_kind_fields should succeed for non-scan kinds with no typed cols");
        assert_eq!(kf, KindFields::Other);
    }

    // ---- sort_claimed_scan_jobs ------------------------------------------
    //
    // Reproduces the ordering bug behind the failing
    // `tests/jobs_repository.rs::claim_scan_jobs_returns_pending_rows_in_priority_then_created_at_order`
    // integration test: PostgreSQL's `UPDATE … RETURNING` does NOT preserve
    // the order chosen in the picking CTE, so the rows the SQL hands back
    // are in executor order. The Rust side must re-sort by
    // `priority DESC, created_at ASC` (with `id` as a deterministic
    // tiebreaker) before returning to the caller.

    fn job_with(id_byte: u8, priority: u8, created_at_secs: i64) -> ScanJob {
        ScanJob {
            id: Uuid::from_bytes([id_byte; 16]),
            artifact_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            content_hash: ContentHash::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            format: "pypi".into(),
            status: JobStatus::Pending,
            attempts: 0,
            locked_by: None,
            locked_until: None,
            last_error: None,
            created_at: DateTime::<Utc>::from_timestamp(created_at_secs, 0).unwrap(),
            updated_at: DateTime::<Utc>::from_timestamp(created_at_secs, 0).unwrap(),
            trigger_source: TriggerSource::Ingest,
            priority,
        }
    }

    #[test]
    fn sort_claimed_scan_jobs_orders_by_priority_desc_then_created_at_asc() {
        // Arbitrary insertion order with mixed priorities + creation times.
        // Expected post-sort: priority 10 first, then 5, then 0; within
        // a priority bucket, earlier created_at first.
        let low = job_with(0xAA, 0, 100); // priority 0,  newest
        let high = job_with(0xBB, 10, 200); // priority 10, latest
        let med = job_with(0xCC, 5, 50); // priority 5,  earliest

        let mut jobs = vec![low.clone(), high.clone(), med.clone()];
        sort_claimed_scan_jobs(&mut jobs);
        let ids: Vec<Uuid> = jobs.iter().map(|j| j.id).collect();
        assert_eq!(
            ids,
            vec![high.id, med.id, low.id],
            "expected priority DESC: high(10) → med(5) → low(0)"
        );
    }

    #[test]
    fn sort_claimed_scan_jobs_breaks_priority_ties_by_created_at_asc() {
        // Two priority-5 rows: one created earlier, one later. Earlier
        // wins. A priority-0 row sits below both.
        let earlier_5 = job_with(0x11, 5, 100);
        let later_5 = job_with(0x22, 5, 200);
        let prio_0 = job_with(0x33, 0, 50); // earliest overall, but lowest priority

        let mut jobs = vec![later_5.clone(), prio_0.clone(), earlier_5.clone()];
        sort_claimed_scan_jobs(&mut jobs);
        let ids: Vec<Uuid> = jobs.iter().map(|j| j.id).collect();
        assert_eq!(
            ids,
            vec![earlier_5.id, later_5.id, prio_0.id],
            "ties broken by created_at ASC; priority always dominates"
        );
    }

    #[test]
    fn sort_claimed_scan_jobs_breaks_full_ties_by_id_for_determinism() {
        // Same priority + same created_at: deterministic id ordering
        // keeps the integration tests reproducible across runs.
        let a = job_with(0x01, 5, 100);
        let b = job_with(0x02, 5, 100);
        let c = job_with(0x03, 5, 100);
        let mut jobs = vec![c.clone(), a.clone(), b.clone()];
        sort_claimed_scan_jobs(&mut jobs);
        let ids: Vec<Uuid> = jobs.iter().map(|j| j.id).collect();
        assert_eq!(ids, vec![a.id, b.id, c.id]);
    }

    // ---- row_to_scan_job mapper tests --------------------------------------
    //
    // Row mapper populates `trigger_source` and `priority`. These tests
    // use a direct DATABASE_URL connection because constructing a `PgRow`
    // outside sqlx is not possible — the integration tests cover the SQL
    // plumbing; the unit-style assertions here pin the field-by-field
    // mapping for the new columns.

    /// Round-trip a freshly inserted `kind='scan'`,
    /// `trigger_source='cron'`, `priority=10` row through
    /// `claim_scan_jobs` and assert the in-memory `ScanJob` exposes
    /// both fields.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn row_to_scan_job_populates_trigger_source_cron_and_priority_10() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        let artifact_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let content_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO public.jobs \
                (kind, artifact_id, repository_id, content_hash, format, \
                 priority, trigger_source, status) \
             VALUES ('scan', $1, $2, $3, 'npm', 10, 'cron', 'pending') \
             RETURNING id",
        )
        .bind(artifact_id)
        .bind(repository_id)
        .bind(content_hash)
        .fetch_one(&pool)
        .await
        .expect("seed scan row");

        let repo = PgJobsRepository::new(pool.clone());
        let claimed = repo
            .claim_scan_jobs("test-worker", 100, Duration::from_secs(60))
            .await
            .expect("claim_scan_jobs");

        let job = claimed
            .into_iter()
            .find(|j| j.id == id)
            .expect("seeded row in claim batch");
        assert_eq!(job.trigger_source, TriggerSource::Cron);
        assert_eq!(job.priority, 10);
    }

    /// Ingest path inserts with the column default `priority=0` and an
    /// explicit `trigger_source='ingest'`. The mapper must round-trip
    /// both unchanged.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn row_to_scan_job_populates_default_ingest_trigger_source_and_priority_0() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        let artifact_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let content_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO public.jobs \
                (kind, artifact_id, repository_id, content_hash, format, \
                 trigger_source, status) \
             VALUES ('scan', $1, $2, $3, 'npm', 'ingest', 'pending') \
             RETURNING id",
        )
        .bind(artifact_id)
        .bind(repository_id)
        .bind(content_hash)
        .fetch_one(&pool)
        .await
        .expect("seed scan row");

        let repo = PgJobsRepository::new(pool.clone());
        let claimed = repo
            .claim_scan_jobs("test-worker", 100, Duration::from_secs(60))
            .await
            .expect("claim_scan_jobs");

        let job = claimed
            .into_iter()
            .find(|j| j.id == id)
            .expect("seeded row in claim batch");
        assert_eq!(job.trigger_source, TriggerSource::Ingest);
        assert_eq!(job.priority, 0);
    }

    // ---- sort_claimed_jobs (cross-kind variant) --------------------------
    //
    // Same `UPDATE … RETURNING` ordering bug as `claim_scan_jobs`: the
    // post-query sort re-establishes `priority DESC, created_at ASC, id ASC`
    // for the multi-kind claim.

    fn job_row_with(id_byte: u8, kind: &str, priority: i16, created_at_secs: i64) -> JobRow {
        let ts = DateTime::<Utc>::from_timestamp(created_at_secs, 0).unwrap();
        JobRow {
            id: Uuid::from_bytes([id_byte; 16]),
            kind: kind.into(),
            status: JobStatus::Pending,
            params: Some(serde_json::json!({})),
            actor_id: None,
            priority,
            trigger_source: "manual".into(),
            created_at: ts,
            updated_at: ts,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
            attempts: 0,
        }
    }

    #[test]
    fn sort_claimed_jobs_orders_by_priority_desc_then_created_at_asc() {
        let low = job_row_with(0xAA, "noop", 0, 100);
        let high = job_row_with(0xBB, "scan", 10, 200);
        let med = job_row_with(0xCC, "staging-sweep", 5, 50);
        let mut jobs = vec![low.clone(), high.clone(), med.clone()];
        sort_claimed_jobs(&mut jobs);
        let ids: Vec<Uuid> = jobs.iter().map(|j| j.id).collect();
        assert_eq!(ids, vec![high.id, med.id, low.id]);
    }

    #[test]
    fn sort_claimed_jobs_breaks_priority_ties_by_created_at_asc() {
        let earlier_5 = job_row_with(0x11, "scan", 5, 100);
        let later_5 = job_row_with(0x22, "scan", 5, 200);
        let prio_0 = job_row_with(0x33, "noop", 0, 50);
        let mut jobs = vec![later_5.clone(), prio_0.clone(), earlier_5.clone()];
        sort_claimed_jobs(&mut jobs);
        let ids: Vec<Uuid> = jobs.iter().map(|j| j.id).collect();
        assert_eq!(ids, vec![earlier_5.id, later_5.id, prio_0.id]);
    }

    #[test]
    fn sort_claimed_jobs_breaks_full_ties_by_id_for_determinism() {
        let a = job_row_with(0x01, "noop", 5, 100);
        let b = job_row_with(0x02, "noop", 5, 100);
        let c = job_row_with(0x03, "noop", 5, 100);
        let mut jobs = vec![c.clone(), a.clone(), b.clone()];
        sort_claimed_jobs(&mut jobs);
        let ids: Vec<Uuid> = jobs.iter().map(|j| j.id).collect();
        assert_eq!(ids, vec![a.id, b.id, c.id]);
    }

    // -- Integration tests (gated on DATABASE_URL) ---------------------------
    //
    // Runtime self-skip (issue #94): `maybe_pool()` returns `None` when
    // `DATABASE_URL` is unset, and each test does
    // `let Some(pool) = maybe_pool().await else { return; };` — a clean,
    // fast no-op under plain `cargo test`, full execution when
    // `DATABASE_URL` is wired:
    //   DATABASE_URL=postgresql://... cargo test -p hort-adapters-postgres

    /// `PgJobsRepository::enqueue_task` inserts a row and returns a Uuid;
    /// the row exists in `jobs` with the expected columns.
    ///
    /// `trigger_source` must be one of the values
    /// `migrations/009_scan_jobs_and_findings.sql`'s `jobs_trigger_source_check`
    /// CHECK constraint allows (`manual`, `cron`, `advisory`, `ingest`,
    /// `seed-import`, `prefetch`, `self_service`, `scheduled`) — a
    /// deterministic failure on any correctly-migrated DB otherwise
    /// (issue #94). `'manual'` is the operator-triggered case this
    /// ad-hoc enqueue actually represents.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn enqueue_task_inserts_row_and_returns_uuid() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());

        let params = serde_json::json!({"dry_run": true});
        // `actor_id` is a nullable FK to `users(id)` (issue #94: a random
        // UUID here violates `jobs_actor_id_fkey` on any correctly-
        // migrated DB — this test only asserts the row/columns, not
        // actor attribution, so `None` (system-triggered) is the
        // correct fixture, not a seeded user row).
        let actor_id = None;
        let outcome = repo
            .enqueue_task("noop", &params, actor_id, 0, "manual", None)
            .await
            .expect("enqueue_task failed");

        // None idempotency_key path returns Enqueued with a fresh
        // non-nil UUID.
        let job_id = match outcome {
            EnqueueOutcome::Enqueued { job_id } => job_id,
            other => panic!("expected Enqueued for None-key path, got {other:?}"),
        };
        assert_ne!(job_id, Uuid::nil());

        // Verify the row exists and has the expected columns.
        let (kind, status): (String, String) =
            sqlx::query_as("SELECT kind, status FROM public.jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&pool)
                .await
                .expect("row not found after enqueue_task");

        assert_eq!(kind, "noop");
        assert_eq!(status, "pending");
    }

    // -----------------------------------------------------------------
    // Cascade tests against the real partial unique indexes
    // (`jobs_prefetch_unique` + `jobs_prefetch_dependencies_unique`)
    // and the retention sweep predicate. Carries `#[serial(hort_pg_db)]`
    // per ADR 0019.
    // -----------------------------------------------------------------

    use hort_domain::ports::jobs_repository::IdempotentEnqueueRow as IER;
    use hort_domain::ports::jobs_repository::PrefetchEnqueueRow as PER;
    use serial_test::serial;

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;
        Some(pool)
    }

    fn cascade_row(kind: &str, target_key: &str) -> PER {
        PER {
            kind: kind.to_string(),
            params: serde_json::json!({"package": "p", "version": "v"}),
            priority: 0,
            trigger_source: "prefetch".to_string(),
            target_key: target_key.to_string(),
        }
    }

    /// Batch INSERT inserts every row when no L3 conflict exists.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn enqueue_prefetch_batch_inserts_every_row_when_no_conflict() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());
        let key = format!("rid|npm|express|{}", Uuid::new_v4());
        let rows = vec![cascade_row("prefetch", &key)];
        let ids = repo
            .enqueue_prefetch_batch(&rows)
            .await
            .expect("enqueue_prefetch_batch");
        assert_eq!(ids.len(), 1);
    }

    /// L3 partial unique index absorbs a duplicate `(kind=prefetch,
    /// target_key)` in-flight enqueue — the second call returns zero
    /// inserted ids.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn enqueue_prefetch_batch_dedup_absorbs_concurrent_repeat() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());
        let key = format!("rid|npm|left-pad|{}", Uuid::new_v4());
        let rows = vec![cascade_row("prefetch", &key)];

        let first = repo
            .enqueue_prefetch_batch(&rows)
            .await
            .expect("first batch");
        assert_eq!(first.len(), 1);

        let second = repo
            .enqueue_prefetch_batch(&rows)
            .await
            .expect("second batch");
        assert_eq!(
            second.len(),
            0,
            "L3 partial unique index must absorb concurrent re-enqueue",
        );
    }

    /// Disjoint per-kind partial unique indexes — a `prefetch` row
    /// and a `prefetch-dependencies` row with the same `target_key`
    /// both insert (they target different partial indexes).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn enqueue_prefetch_batch_kinds_disjoint_dedup_namespace() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());
        let key = format!("rid|npm|shared-key|{}", Uuid::new_v4());
        let rows = vec![
            cascade_row("prefetch", &key),
            cascade_row("prefetch-dependencies", &key),
        ];
        let ids = repo
            .enqueue_prefetch_batch(&rows)
            .await
            .expect("enqueue_prefetch_batch");
        assert_eq!(
            ids.len(),
            2,
            "the two partial unique indexes are per-kind disjoint — both rows insert",
        );
    }

    fn idempotent_row(kind: &str, idempotency_key: &str) -> IER {
        IER {
            kind: kind.to_string(),
            params: serde_json::json!({"child_digest": "sha256:…"}),
            priority: 0,
            trigger_source: "ingest".to_string(),
            idempotency_key: IdempotencyKey::try_from(idempotency_key.to_string())
                .expect("valid idempotency key"),
        }
    }

    /// One statement inserts the whole cohort when no key collides, and
    /// returns one id per inserted row.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn enqueue_idempotent_batch_inserts_every_row_when_no_conflict() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());
        let run = Uuid::new_v4();
        let rows = vec![
            idempotent_row("oci-index-child-ingest", &format!("oci-child:{run}:a")),
            idempotent_row("oci-index-child-ingest", &format!("oci-child:{run}:b")),
        ];
        let ids = repo
            .enqueue_idempotent_batch(&rows)
            .await
            .expect("enqueue_idempotent_batch");
        assert_eq!(ids.len(), 2);
    }

    /// `jobs_idempotency_key_uq` absorbs a repeat cohort: the second
    /// call inserts nothing and errors on nothing. This is the batched
    /// counterpart to the single-row `enqueue_task` `Duplicate` proof —
    /// there the conflict is REPORTED per row, here it is absorbed by
    /// the index, and the caller reads the dedup count as
    /// `rows.len() - ids.len()`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn enqueue_idempotent_batch_dedup_absorbs_repeat_cohort() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());
        let run = Uuid::new_v4();
        let rows = vec![
            idempotent_row("oci-index-child-ingest", &format!("oci-child:{run}:a")),
            idempotent_row("oci-index-child-ingest", &format!("oci-child:{run}:b")),
        ];

        let first = repo
            .enqueue_idempotent_batch(&rows)
            .await
            .expect("first cohort");
        assert_eq!(first.len(), 2);

        // A partly-overlapping second cohort: one already-seen key, one
        // fresh. Exactly the shape a re-pull of an index that gained a
        // platform produces.
        let second_rows = vec![
            idempotent_row("oci-index-child-ingest", &format!("oci-child:{run}:b")),
            idempotent_row("oci-index-child-ingest", &format!("oci-child:{run}:c")),
        ];
        let second = repo
            .enqueue_idempotent_batch(&second_rows)
            .await
            .expect("second cohort");
        assert_eq!(
            second.len(),
            1,
            "the unique index absorbs the repeated key and the statement still inserts the \
             fresh one — a conflict is not an error for this entry point",
        );
    }

    /// Two rows carrying the SAME key inside ONE call collapse to one
    /// insert rather than failing the statement. An index may legally
    /// declare the same child digest under two platform descriptors, so
    /// the cohort builder does not have to pre-deduplicate.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn enqueue_idempotent_batch_collapses_duplicate_keys_within_one_call() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());
        let key = format!("oci-child:{}:dup", Uuid::new_v4());
        let rows = vec![
            idempotent_row("oci-index-child-ingest", &key),
            idempotent_row("oci-index-child-ingest", &key),
        ];
        let ids = repo
            .enqueue_idempotent_batch(&rows)
            .await
            .expect("enqueue_idempotent_batch");
        assert_eq!(
            ids.len(),
            1,
            "ON CONFLICT DO NOTHING resolves an intra-statement conflict the same way it \
             resolves one against a committed row",
        );
    }

    /// An empty cohort is a no-op that never reaches the database — the
    /// facade's "index declared no children" path must not synthesise a
    /// `VALUES` list with no rows (a syntax error).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn enqueue_idempotent_batch_with_no_rows_is_a_no_op() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());
        let ids = repo
            .enqueue_idempotent_batch(&[])
            .await
            .expect("empty batch is Ok");
        assert!(ids.is_empty());
    }

    /// Retention sweep deletes `completed` + `failed` rows of the
    /// pull-through ingest cascade (`prefetch%` plus
    /// `oci-index-child-ingest`) older than the horizon, leaves
    /// `pending`/`running` rows and foreign kinds alone.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn retention_sweep_deletes_only_terminal_prefetch_rows_older_than_horizon() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());

        // Seed: one row each (pending, running, completed-old,
        // failed-old, completed-fresh) under unique target_keys.
        let suffix = Uuid::new_v4();
        let mk = |status: &str, kind: &str, age_secs: i64| {
            let key = format!("{suffix}|npm|p|{status}-{kind}");
            (status.to_string(), kind.to_string(), key, age_secs)
        };
        let fixtures = vec![
            mk("pending", "prefetch", 1_000_000),
            mk("running", "prefetch", 1_000_000),
            mk("completed", "prefetch", 1_000_000),
            mk("failed", "prefetch-dependencies", 1_000_000),
            mk("completed", "prefetch", 0),
            // The eager index-child ingest rides this sweep too.
            mk("completed", "oci-index-child-ingest", 1_000_000),
            mk("failed", "oci-index-child-ingest", 1_000_000),
            mk("completed", "oci-index-child-ingest", 0),
            mk("running", "oci-index-child-ingest", 1_000_000),
            // A foreign kind whose newest terminal row IS durable state —
            // widening the predicate must never reach it.
            mk("completed", "verify-event-chain", 1_000_000),
            // `prefetch-tick` matches the `prefetch%` prefix by name but
            // is carved out: the rotation's keyset cursor lives in its
            // newest `completed` row's `result_summary`, and this sweep
            // has no keep-newest clause to protect it. Both rows must
            // survive — even the superseded one, because the carve-out is
            // by kind, not by rank.
            mk("completed", "prefetch-tick", 1_000_000),
            mk("failed", "prefetch-tick", 900_000),
        ];
        for (status, kind, key, age_secs) in &fixtures {
            sqlx::query(
                "INSERT INTO public.jobs \
                   (kind, params, priority, trigger_source, target_key, status, \
                    created_at, updated_at) \
                 VALUES ($1, '{}'::jsonb, 0, 'prefetch', $2, $3::text, \
                         now() - ($4::int || ' seconds')::interval, \
                         now() - ($4::int || ' seconds')::interval)",
            )
            .bind(kind)
            .bind(key)
            .bind(status)
            .bind(*age_secs)
            .execute(&pool)
            .await
            .expect("seed row");
        }

        // Sweep: horizon = 1 day. The four old-and-terminal in-scope rows
        // qualify; the pending + running + fresh-completed rows and the
        // foreign kind do not.
        let deleted = repo
            .delete_terminal_prefetch_rows_older_than(Duration::from_secs(86_400))
            .await
            .expect("retention sweep");
        assert_eq!(
            deleted, 4,
            "exactly the four old-terminal in-scope rows are deleted (not pending/running, \
             not fresh, not a foreign kind's durable state, and not `prefetch-tick` — \
             which matches the prefix but is swept by the generic sweep instead)",
        );

        // Cleanup: drop the remaining seeded rows for isolation.
        let keys: Vec<String> = fixtures.into_iter().map(|(_, _, k, _)| k).collect();
        sqlx::query("DELETE FROM public.jobs WHERE target_key = ANY($1)")
            .bind(&keys)
            .execute(&pool)
            .await
            .expect("cleanup seeded rows");
    }

    /// Retention sweep deletes only terminal `kind='scan'` rows older
    /// than the horizon. Seeds an aged+fresh terminal scan row, a
    /// pending and a running scan row (never touched regardless of
    /// age), plus an aged terminal `verify-event-chain` row and an
    /// aged terminal `prefetch` row (foreign kinds, never touched) —
    /// pins the exact-kind scope: only `kind = 'scan'` terminal rows
    /// are eligible, never another kind's durable state.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn scan_retention_sweep_deletes_only_terminal_scan_rows_older_than_horizon() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());

        let suffix = Uuid::new_v4();
        let mk = |status: &str, kind: &str, age_secs: i64| {
            let key = format!("{suffix}|{kind}|{status}");
            (status.to_string(), kind.to_string(), key, age_secs)
        };
        let fixtures = vec![
            mk("completed", "scan", 1_000_000), // aged terminal scan — deleted
            mk("failed", "scan", 1_000_000),    // aged terminal scan — deleted
            mk("completed", "scan", 0),         // fresh terminal scan — kept
            mk("pending", "scan", 1_000_000),   // non-terminal — kept regardless of age
            mk("running", "scan", 1_000_000),   // non-terminal — kept regardless of age
            mk("completed", "verify-event-chain", 1_000_000), // foreign kind — kept
            mk("completed", "prefetch", 1_000_000), // foreign kind — kept
        ];
        for (status, kind, key, age_secs) in &fixtures {
            sqlx::query(
                "INSERT INTO public.jobs \
                   (kind, params, priority, trigger_source, target_key, status, \
                    created_at, updated_at) \
                 VALUES ($1, '{}'::jsonb, 0, 'cron', $2, $3::text, \
                         now() - ($4::int || ' seconds')::interval, \
                         now() - ($4::int || ' seconds')::interval)",
            )
            .bind(kind)
            .bind(key)
            .bind(status)
            .bind(*age_secs)
            .execute(&pool)
            .await
            .expect("seed row");
        }

        let deleted = repo
            .delete_terminal_scan_rows_older_than(Duration::from_secs(86_400))
            .await
            .expect("retention sweep");
        assert_eq!(
            deleted, 2,
            "exactly the two aged-terminal scan rows are deleted (not pending/running scan, \
             not fresh scan, not foreign kinds)",
        );

        // Cleanup: drop the remaining seeded rows for isolation.
        let keys: Vec<String> = fixtures.into_iter().map(|(_, _, k, _)| k).collect();
        sqlx::query("DELETE FROM public.jobs WHERE target_key = ANY($1)")
            .bind(&keys)
            .execute(&pool)
            .await
            .expect("cleanup seeded rows");
    }

    // -----------------------------------------------------------------
    // Generic (`other kind`) retention sweep — the horizon for every
    // `jobs.kind` the two kind-specific sweeps do not reach. Carries
    // `#[serial(hort_pg_db)]` per ADR 0019; note that the per-test
    // database `maybe_pool()` creates is NOT isolation from
    // cluster-global work, which is what the serial key covers.
    // -----------------------------------------------------------------

    /// Seed one `jobs` row with an explicit age, returning its id.
    ///
    /// `age_secs` sets `created_at` and `updated_at` to the same instant:
    /// the horizon predicate reads `updated_at` while the
    /// newest-terminal-row protection reads `created_at`, and a real row
    /// written through the port has both advancing together. A
    /// `'completed'` row also gets `completed_at` at that instant,
    /// matching what `mark_completed` / `record_run_completion` write —
    /// that column is what `last_completed_at_by_kind` reads.
    async fn seed_aged_row(pool: &PgPool, kind: &str, status: &str, age_secs: i32) -> Uuid {
        seed_aged_row_with_summary(pool, kind, status, age_secs, None).await
    }

    /// [`seed_aged_row`] plus an explicit `result_summary` — the column
    /// `last_result_summary_by_kind` reads back as cross-tick state.
    async fn seed_aged_row_with_summary(
        pool: &PgPool,
        kind: &str,
        status: &str,
        age_secs: i32,
        summary: Option<JsonValue>,
    ) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO public.jobs \
               (kind, params, priority, trigger_source, status, result_summary, \
                created_at, updated_at, completed_at) \
             VALUES ($1, '{}'::jsonb, 0, 'cron', $2::text, $4, \
                     now() - ($3::int || ' seconds')::interval, \
                     now() - ($3::int || ' seconds')::interval, \
                     CASE WHEN $2::text = 'completed' \
                          THEN now() - ($3::int || ' seconds')::interval END) \
             RETURNING id",
        )
        .bind(kind)
        .bind(status)
        .bind(age_secs)
        .bind(summary.map(sqlx::types::Json))
        .fetch_one(pool)
        .await
        .expect("seed aged jobs row")
    }

    /// Whether a seeded row is still present.
    async fn row_present(pool: &PgPool, id: Uuid) -> bool {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM public.jobs WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("count seeded row");
        n == 1
    }

    /// The newest terminal row of `kind` by `created_at` — the
    /// `ORDER BY created_at DESC LIMIT 1` read shape a
    /// latest-job-decides-the-predicate consumer uses (the artifact
    /// rescan-stranding probe is the live example).
    async fn newest_terminal_row_id(pool: &PgPool, kind: &str) -> Option<Uuid> {
        sqlx::query_scalar(
            "SELECT id FROM public.jobs \
              WHERE kind = $1 AND status IN ('completed', 'failed') \
              ORDER BY created_at DESC \
              LIMIT 1",
        )
        .bind(kind)
        .fetch_optional(pool)
        .await
        .expect("newest terminal row")
    }

    /// One day, the horizon every test below sweeps with.
    const TEST_HORIZON: Duration = Duration::from_secs(86_400);

    /// The generic horizon deletes aged terminal rows of the kinds the
    /// two kind-specific sweeps do not reach — and only those. Runs
    /// against a per-test database, so the deleted count is exact.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn other_kind_retention_sweep_deletes_only_aged_terminal_rows_of_unswept_kinds() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());

        // `noop`: three aged `completed` rows plus a newer aged `failed`
        // one. The newest `completed` is what `last_completed_at_by_kind`
        // would read; the `failed` row is the newest terminal row by
        // `created_at`. Both survive; the two superseded `completed` rows
        // age out.
        let noop_oldest = seed_aged_row(&pool, "noop", "completed", 400_000).await;
        let noop_older = seed_aged_row(&pool, "noop", "completed", 300_000).await;
        let noop_newest_completed = seed_aged_row(&pool, "noop", "completed", 200_000).await;
        let noop_newest_terminal = seed_aged_row(&pool, "noop", "failed", 100_000).await;

        // `cron-rescan-tick`: aged `failed` rows only. The kind has never
        // completed, so `max(completed_at) FILTER (…)` is NULL for it and
        // only the newest-terminal protection applies — the FILTER-NULL
        // path.
        let tick_oldest = seed_aged_row(&pool, "cron-rescan-tick", "failed", 400_000).await;
        let tick_older = seed_aged_row(&pool, "cron-rescan-tick", "failed", 300_000).await;
        let tick_newest = seed_aged_row(&pool, "cron-rescan-tick", "failed", 200_000).await;

        // The sweep's own kind is inside its own predicate — it reclaims
        // its own history the way its two siblings do.
        let self_old = seed_aged_row(&pool, "jobs-row-retention-sweep", "completed", 400_000).await;
        let self_newest =
            seed_aged_row(&pool, "jobs-row-retention-sweep", "completed", 100_000).await;

        // Non-terminal rows are never touched, at any age. A row left
        // `running` by a crashed worker is deliberately among them: an
        // expired claim lease does not distinguish a dead worker from a
        // task slower than its lease.
        let pending = seed_aged_row(&pool, "seed-import", "pending", 400_000).await;
        let running = seed_aged_row(&pool, "seed-import", "running", 400_000).await;

        // Fresh terminal rows are inside the horizon.
        let fresh_completed = seed_aged_row(&pool, "policy-reevaluation", "completed", 0).await;
        let fresh_failed = seed_aged_row(&pool, "policy-reevaluation", "failed", 10).await;

        // The two kind-specific sweeps own these kinds. This sweep must
        // not reach them even when a row is aged, terminal AND superseded
        // by a newer row of its own kind — otherwise two horizons would
        // be in force per kind and the shorter would silently win.
        let scan_old = seed_aged_row(&pool, "scan", "completed", 400_000).await;
        let scan_newer = seed_aged_row(&pool, "scan", "failed", 300_000).await;
        let prefetch_old = seed_aged_row(&pool, "prefetch", "completed", 400_000).await;
        let prefetch_newer = seed_aged_row(&pool, "prefetch", "completed", 300_000).await;
        let prefetch_deps = seed_aged_row(&pool, "prefetch-dependencies", "failed", 400_000).await;
        let prefetch_sweep =
            seed_aged_row(&pool, "prefetch-row-retention-sweep", "completed", 400_000).await;
        let child_old = seed_aged_row(&pool, "oci-index-child-ingest", "completed", 400_000).await;
        let child_newer =
            seed_aged_row(&pool, "oci-index-child-ingest", "completed", 300_000).await;

        // `prefetch-tick` is the one `prefetch%` kind this sweep DOES own:
        // it is a scheduled tick, not cascade work, and its newest
        // `completed` row carries the rotation's keyset cursor — so it
        // needs the keep-newest clause the cascade sweep does not have.
        let prefetch_tick_old = seed_aged_row(&pool, "prefetch-tick", "completed", 400_000).await;
        let prefetch_tick_newer = seed_aged_row(&pool, "prefetch-tick", "completed", 300_000).await;

        let deleted = repo
            .delete_terminal_other_kind_rows_older_than(TEST_HORIZON)
            .await
            .expect("generic retention sweep");
        assert_eq!(
            deleted, 6,
            "exactly the six superseded, aged, terminal, in-scope rows are deleted: two \
             `noop` completions, two `cron-rescan-tick` failures, one of the sweep's own, \
             and the superseded `prefetch-tick` completion",
        );

        for (id, why) in [
            (noop_oldest, "superseded aged `noop` completion"),
            (noop_older, "superseded aged `noop` completion"),
            (tick_oldest, "superseded aged `cron-rescan-tick` failure"),
            (tick_older, "superseded aged `cron-rescan-tick` failure"),
            (self_old, "superseded aged row of the sweep's own kind"),
            (
                prefetch_tick_old,
                "superseded aged `prefetch-tick` completion — the kind is swept here",
            ),
        ] {
            assert!(!row_present(&pool, id).await, "{why} must be deleted");
        }

        for (id, why) in [
            (
                noop_newest_completed,
                "newest `noop` completion is gauge state",
            ),
            (
                noop_newest_terminal,
                "newest terminal `noop` row is predicate state",
            ),
            (
                tick_newest,
                "newest terminal `cron-rescan-tick` row is predicate state",
            ),
            (
                self_newest,
                "the sweep keeps its own newest row like any other kind",
            ),
            (pending, "`pending` rows are claim-pending, never swept"),
            (
                running,
                "`running` rows may be genuinely in flight, never swept",
            ),
            (fresh_completed, "inside the horizon"),
            (fresh_failed, "inside the horizon"),
            (scan_old, "`scan` belongs to the scan-row sweep"),
            (scan_newer, "`scan` belongs to the scan-row sweep"),
            (prefetch_old, "`prefetch%` belongs to the cascade sweep"),
            (prefetch_newer, "`prefetch%` belongs to the cascade sweep"),
            (prefetch_deps, "`prefetch%` belongs to the cascade sweep"),
            (prefetch_sweep, "`prefetch%` belongs to the cascade sweep"),
            (
                prefetch_tick_newer,
                "newest `prefetch-tick` completion carries the rotation cursor",
            ),
            (
                child_old,
                "`oci-index-child-ingest` belongs to the cascade sweep",
            ),
            (
                child_newer,
                "`oci-index-child-ingest` belongs to the cascade sweep",
            ),
        ] {
            assert!(row_present(&pool, id).await, "{why} — must survive");
        }
    }

    /// **Both** boot-time liveness gauges read the newest `completed` row
    /// of their kind through `last_completed_at_by_kind`, and the sweep
    /// must leave that value — and therefore the gauge verdict —
    /// unchanged. Checked through the consumer, not by row count.
    ///
    /// The `staging-sweep` fixture is the case that decides the design:
    /// the sweep ran, then started failing, so its newest **terminal**
    /// row is a failure. A sweep that retained only the newest terminal
    /// row would drop the `completed` row underneath it, and
    /// `last_completed_at_by_kind` — which filters `status = 'completed'`
    /// — would answer `None`. That is `NeverRan`, whose operator-facing
    /// message is "upgraded without enabling the CronJob", for a sweep
    /// that demonstrably ran.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn other_kind_retention_sweep_leaves_both_liveness_gauges_unchanged() {
        use hort_domain::policy::{
            evaluate_event_chain_verify_liveness, evaluate_staging_sweep_liveness,
            EventChainVerifyLiveness, StagingSweepLiveness,
        };

        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());

        // `hort_staging_sweep_overdue` — expected interval 300 s,
        // staleness multiplier 3.
        let ss_superseded = seed_aged_row(&pool, "staging-sweep", "completed", 500_000).await;
        let ss_breadcrumb = seed_aged_row(&pool, "staging-sweep", "completed", 400_000).await;
        let ss_newest_terminal = seed_aged_row(&pool, "staging-sweep", "failed", 100_000).await;

        // `hort_event_chain_verify_overdue` — expected interval 86400 s,
        // staleness multiplier 3. The breadcrumb here is also the newest
        // terminal row, so one protection covers it twice; the point is
        // that the superseded completion still ages out.
        let vec_superseded = seed_aged_row(&pool, "verify-event-chain", "completed", 500_000).await;
        let vec_breadcrumb = seed_aged_row(&pool, "verify-event-chain", "completed", 300_000).await;

        let before_ss = repo
            .last_completed_at_by_kind("staging-sweep")
            .await
            .expect("staging-sweep last completion (before)");
        let before_vec = repo
            .last_completed_at_by_kind("verify-event-chain")
            .await
            .expect("verify-event-chain last completion (before)");
        assert!(
            before_ss.is_some() && before_vec.is_some(),
            "fixture precondition: both kinds have a completion on record",
        );

        let deleted = repo
            .delete_terminal_other_kind_rows_older_than(TEST_HORIZON)
            .await
            .expect("generic retention sweep");
        assert_eq!(
            deleted, 2,
            "only the two superseded completions age out — the fixture is not vacuous, \
             the sweep really did delete rows of both gauge-bearing kinds",
        );
        assert!(!row_present(&pool, ss_superseded).await);
        assert!(!row_present(&pool, vec_superseded).await);
        assert!(row_present(&pool, ss_breadcrumb).await);
        assert!(row_present(&pool, ss_newest_terminal).await);
        assert!(row_present(&pool, vec_breadcrumb).await);

        let after_ss = repo
            .last_completed_at_by_kind("staging-sweep")
            .await
            .expect("staging-sweep last completion (after)");
        let after_vec = repo
            .last_completed_at_by_kind("verify-event-chain")
            .await
            .expect("verify-event-chain last completion (after)");
        assert_eq!(
            before_ss, after_ss,
            "the staging-sweep liveness input must survive the sweep verbatim",
        );
        assert_eq!(
            before_vec, after_vec,
            "the event-chain verify liveness input must survive the sweep verbatim",
        );

        // The gauge verdicts themselves, not just their input. Same
        // wall-clock for both sides so only the port read can differ.
        let now = Utc::now();
        let ss_interval = Duration::from_secs(300);
        let vec_interval = Duration::from_secs(86_400);
        assert_eq!(
            evaluate_staging_sweep_liveness(before_ss, now, ss_interval, 3),
            evaluate_staging_sweep_liveness(after_ss, now, ss_interval, 3),
            "hort_staging_sweep_overdue must read identically across the sweep",
        );
        assert_eq!(
            evaluate_event_chain_verify_liveness(before_vec, now, vec_interval, 3),
            evaluate_event_chain_verify_liveness(after_vec, now, vec_interval, 3),
            "hort_event_chain_verify_overdue must read identically across the sweep",
        );

        // Equality alone would also hold if both sides were `NeverRan`,
        // which is precisely the failure this test exists to catch. Pin
        // the surviving verdict as `Overdue` — the outage diagnosis —
        // rather than `NeverRan`, the never-enabled one.
        assert!(
            matches!(
                evaluate_staging_sweep_liveness(after_ss, now, ss_interval, 3),
                StagingSweepLiveness::Overdue { .. }
            ),
            "the surviving verdict must be Overdue (the sweep stopped), not NeverRan \
             (the CronJob was never enabled)",
        );
        assert!(
            matches!(
                evaluate_event_chain_verify_liveness(after_vec, now, vec_interval, 3),
                EventChainVerifyLiveness::Overdue { .. }
            ),
            "the surviving verdict must be Overdue (the verifier stopped), not NeverRan",
        );
    }

    /// The latest-terminal-row read shape — `ORDER BY created_at DESC
    /// LIMIT 1`, which is how a latest-job-decides-the-predicate consumer
    /// reads `jobs` — resolves to the same row before and after the
    /// sweep. Deleting the newest row while an older one of a different
    /// status survived would flip such a predicate silently.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn other_kind_retention_sweep_keeps_the_newest_terminal_row_per_kind() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());

        let superseded =
            seed_aged_row(&pool, "quarantine-release-sweep", "completed", 500_000).await;
        let newest_completed =
            seed_aged_row(&pool, "quarantine-release-sweep", "completed", 400_000).await;
        let newest_terminal =
            seed_aged_row(&pool, "quarantine-release-sweep", "failed", 200_000).await;

        let before = newest_terminal_row_id(&pool, "quarantine-release-sweep").await;
        assert_eq!(
            before,
            Some(newest_terminal),
            "fixture precondition: the newest terminal row is the failure",
        );

        let deleted = repo
            .delete_terminal_other_kind_rows_older_than(TEST_HORIZON)
            .await
            .expect("generic retention sweep");
        assert_eq!(deleted, 1, "only the superseded completion ages out");
        assert!(!row_present(&pool, superseded).await);
        assert!(row_present(&pool, newest_completed).await);

        let after = newest_terminal_row_id(&pool, "quarantine-release-sweep").await;
        assert_eq!(
            after, before,
            "the latest-terminal-row predicate must resolve to the same row across the sweep",
        );
    }

    /// The cross-tick rotation cursor rides the newest completed row's
    /// `result_summary` and is read back by
    /// `last_result_summary_by_kind`. `prefetch-tick` is swept HERE, so
    /// the cursor's survival rests on this sweep's keep-newest clause
    /// rather than on an exclusion: the superseded tick row carrying a
    /// stale cursor must age out while the current one stays readable.
    /// `eventstore-checkpoint` covers the same shape for a kind whose
    /// newest completion is NOT its newest terminal row.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn other_kind_retention_sweep_keeps_the_newest_result_summary_readable() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());

        let stale_cursor = serde_json::json!({"cursor": {"position": "after_repo",
            "repository_id": "00000000-0000-0000-0000-000000000001"}});
        let cursor = serde_json::json!({"cursor": {"position": "after_repo",
            "repository_id": "00000000-0000-0000-0000-000000000002"}});
        let tick_superseded = seed_aged_row_with_summary(
            &pool,
            "prefetch-tick",
            "completed",
            500_000,
            Some(stale_cursor),
        )
        .await;
        let tick_row = seed_aged_row_with_summary(
            &pool,
            "prefetch-tick",
            "completed",
            400_000,
            Some(cursor.clone()),
        )
        .await;

        let stale = serde_json::json!({"checkpointed_through": 1});
        let current = serde_json::json!({"checkpointed_through": 2});
        let ck_superseded = seed_aged_row_with_summary(
            &pool,
            "eventstore-checkpoint",
            "completed",
            500_000,
            Some(stale),
        )
        .await;
        let ck_current = seed_aged_row_with_summary(
            &pool,
            "eventstore-checkpoint",
            "completed",
            300_000,
            Some(current.clone()),
        )
        .await;
        // A later failure, so `ck_current` is NOT the newest terminal row
        // of its kind: the newest-completion protection is the only thing
        // standing between the cursor and the horizon here.
        let ck_failed = seed_aged_row(&pool, "eventstore-checkpoint", "failed", 200_000).await;

        let deleted = repo
            .delete_terminal_other_kind_rows_older_than(TEST_HORIZON)
            .await
            .expect("generic retention sweep");
        assert_eq!(
            deleted, 2,
            "the two superseded completions age out — one `eventstore-checkpoint`, \
             one `prefetch-tick` — and nothing else",
        );
        assert!(row_present(&pool, ck_failed).await);
        assert!(!row_present(&pool, ck_superseded).await);
        assert!(row_present(&pool, ck_current).await);
        assert!(!row_present(&pool, tick_superseded).await);
        assert!(row_present(&pool, tick_row).await);

        assert_eq!(
            repo.last_result_summary_by_kind("prefetch-tick")
                .await
                .expect("prefetch-tick summary"),
            Some(cursor),
            "the rotation resumes from the cursor it wrote, not from the beginning — \
             this sweep owns `prefetch-tick` and its keep-newest clause is what \
             protects the cursor",
        );
        assert_eq!(
            repo.last_result_summary_by_kind("eventstore-checkpoint")
                .await
                .expect("eventstore-checkpoint summary"),
            Some(current),
            "the newest completion's summary survives its superseded predecessors",
        );
    }

    /// A kind with a single aged terminal row keeps it: the row is both
    /// the newest completion and the newest terminal row, so the horizon
    /// can never take a kind's last trace of having run.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn other_kind_retention_sweep_never_empties_a_kind() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());

        let lone_completed =
            seed_aged_row(&pool, "service-account-rotation", "completed", 900_000).await;
        let lone_failed = seed_aged_row(&pool, "replay-seen-prune", "failed", 900_000).await;

        let deleted = repo
            .delete_terminal_other_kind_rows_older_than(TEST_HORIZON)
            .await
            .expect("generic retention sweep");
        assert_eq!(deleted, 0, "a kind's only terminal row is never swept");
        assert!(row_present(&pool, lone_completed).await);
        assert!(row_present(&pool, lone_failed).await);
    }

    // -----------------------------------------------------------------
    // `record_run_completion` + `last_completed_at_by_kind` round-trip.
    // Carries `#[serial(hort_pg_db)]` per ADR 0019 (the suite runs in
    // parallel against one shared backend). Silently skips if
    // `DATABASE_URL` is unset (expected locally).
    // -----------------------------------------------------------------

    /// `record_run_completion` inserts a terminal `completed` row whose
    /// `completed_at` is then the value `last_completed_at_by_kind`
    /// returns. Exercises the real
    /// INSERT against migration-009's `kind` + `status` + `trigger_source`
    /// CHECK constraints (the row would be rejected if any literal were
    /// invalid) plus the `MAX(completed_at)` read.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn record_run_completion_round_trips_through_last_completed_at_by_kind() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());

        // No verify run yet → the liveness "never ran" input.
        let before = repo
            .last_completed_at_by_kind("verify-event-chain")
            .await
            .expect("last_completed_at_by_kind (none)");
        assert_eq!(
            before, None,
            "an isolated DB has no verify-event-chain completion yet",
        );

        // Record a completion at a fixed instant (truncated to whole
        // seconds — Postgres `timestamptz` keeps microseconds, but the
        // liveness predicate only reads whole-second age, and chrono
        // round-trips microseconds losslessly so an exact compare holds).
        let at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        repo.record_run_completion("verify-event-chain", at)
            .await
            .expect("record_run_completion inserts a valid jobs row");

        // The newest completed timestamp for the kind is exactly `at`.
        let after = repo
            .last_completed_at_by_kind("verify-event-chain")
            .await
            .expect("last_completed_at_by_kind (some)")
            .expect("a completion was recorded");
        assert_eq!(after, at, "completed_at must round-trip exactly");

        // The row carries the schema defaults + the explicit terminal
        // status and the `'scheduled'` trigger_source.
        let (status, trigger_source, priority): (String, String, i16) = sqlx::query_as(
            "SELECT status, trigger_source, priority \
             FROM public.jobs \
             WHERE kind = 'verify-event-chain' \
             ORDER BY completed_at DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("read back the recorded row");
        assert_eq!(status, "completed");
        assert_eq!(trigger_source, "scheduled");
        assert_eq!(priority, 0, "priority rides the schema DEFAULT 0");

        // A second, newer completion advances the MAX.
        let later = at + chrono::Duration::seconds(120);
        repo.record_run_completion("verify-event-chain", later)
            .await
            .expect("record a second completion");
        let newest = repo
            .last_completed_at_by_kind("verify-event-chain")
            .await
            .expect("last_completed_at_by_kind (newest)")
            .expect("a completion was recorded");
        assert_eq!(newest, later, "MAX(completed_at) tracks the newest run");
    }

    /// `last_result_summary_by_kind` — the cross-tick rotation-state read
    /// `PrefetchTickHandler` uses. No completed row yet → `None`; after
    /// `mark_completed` writes a summary, the SAME kind's next read gets
    /// it back; a NEWER completion for the kind supersedes the older one.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn last_result_summary_by_kind_round_trips_the_newest_completion() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());

        let before = repo
            .last_result_summary_by_kind("prefetch-tick")
            .await
            .expect("last_result_summary_by_kind (none)");
        assert_eq!(
            before, None,
            "an isolated DB has no prior prefetch-tick run"
        );

        let first_summary = serde_json::json!({ "cursor": { "position": "after_repo", "repository_id": Uuid::new_v4() } });
        let first_id = match repo
            .enqueue_task(
                "prefetch-tick",
                &serde_json::json!({}),
                None,
                10,
                "cron",
                None,
            )
            .await
            .expect("enqueue_task")
        {
            EnqueueOutcome::Enqueued { job_id } => job_id,
            other => panic!("expected Enqueued, got {other:?}"),
        };
        repo.mark_completed(first_id, first_summary.clone())
            .await
            .expect("mark_completed (first)");

        let after_first = repo
            .last_result_summary_by_kind("prefetch-tick")
            .await
            .expect("last_result_summary_by_kind (first)");
        assert_eq!(after_first, Some(first_summary));

        // A second, later completion for the same kind supersedes it —
        // this is exactly how the next tick's fresh job row reads back
        // the PREVIOUS tick's cursor. The short sleep guarantees a
        // distinct `completed_at` (the column is set via `now()`
        // inside `mark_completed`, not caller-supplied).
        tokio::time::sleep(Duration::from_millis(10)).await;
        let second_summary = serde_json::json!({ "cursor": null });
        let second_id = match repo
            .enqueue_task(
                "prefetch-tick",
                &serde_json::json!({}),
                None,
                10,
                "cron",
                None,
            )
            .await
            .expect("enqueue_task")
        {
            EnqueueOutcome::Enqueued { job_id } => job_id,
            other => panic!("expected Enqueued, got {other:?}"),
        };
        repo.mark_completed(second_id, second_summary.clone())
            .await
            .expect("mark_completed (second)");

        let after_second = repo
            .last_result_summary_by_kind("prefetch-tick")
            .await
            .expect("last_result_summary_by_kind (second)");
        assert_eq!(after_second, Some(second_summary));

        sqlx::query("DELETE FROM public.jobs WHERE id = ANY($1)")
            .bind([first_id, second_id])
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    /// Regression (admin-task read 500): a completed job's
    /// `result_summary` is a `jsonb` column, so the row mapper MUST decode
    /// it as `serde_json::Value` — decoding it as `String` is a sqlx type
    /// mismatch that errors on every non-NULL value, 500-ing
    /// `GET /api/v1/admin/tasks` and `…/tasks/:id` for any completed job.
    /// Inserts/pending rows have a NULL summary (NULL short-circuits the
    /// decode), which is why writes and `task invoke` stayed green while
    /// reads of finished jobs blew up.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn get_and_list_decode_completed_job_jsonb_result_summary() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgJobsRepository::new(pool.clone());

        // Enqueue a task, then complete it with a NON-NULL jsonb summary.
        let params = serde_json::json!({ "dry_run": true });
        let job_id = match repo
            .enqueue_task("noop", &params, None, 0, "manual", None)
            .await
            .expect("enqueue_task")
        {
            EnqueueOutcome::Enqueued { job_id } => job_id,
            other => panic!("expected Enqueued, got {other:?}"),
        };
        let summary = serde_json::json!({ "scanned": 3, "ok": true });
        repo.mark_completed(job_id, summary.clone())
            .await
            .expect("mark_completed");

        // get_job must DECODE the jsonb result_summary. The bug surfaces
        // here as a `DomainError::Invariant("jobs row decode failed: …
        // String is not compatible with JSONB")`.
        let row = repo
            .get_job(job_id)
            .await
            .expect("get_job must decode a completed job's jsonb result_summary")
            .expect("row present");
        assert_eq!(
            row.result_summary.as_ref(),
            Some(&summary),
            "the jsonb summary round-trips as a structured value",
        );

        // list_jobs decodes the same row inside its page-mapping loop.
        let page = repo
            .list_jobs(
                ListJobsFilter {
                    kind: Some("noop".to_string()),
                    status: None,
                },
                200,
                None,
            )
            .await
            .expect("list_jobs must decode the page including the completed row");
        assert!(
            page.items.iter().any(|r| r.id == job_id),
            "the completed job appears in the list page",
        );

        // Cleanup — this DB is shared across serial DB tests.
        sqlx::query("DELETE FROM public.jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}
