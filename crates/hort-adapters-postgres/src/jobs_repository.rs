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
    ScanJob, ScanKindFields, TriggerSource,
};
use hort_domain::types::{ContentHash, IdempotencyKey};
use serde_json::Value as JsonValue;

use crate::{map_sqlx_error, BoxFuture};

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
const CLAIM_PENDING_BY_KINDS_SQL: &str = "WITH claimed AS (\n\
                     SELECT id FROM public.jobs\n\
                     WHERE status = 'pending'\n\
                       AND kind = ANY($1::text[])\n\
                       AND (locked_until IS NULL OR locked_until < now())\n\
                     ORDER BY priority DESC, created_at ASC\n\
                     FOR UPDATE SKIP LOCKED\n\
                     LIMIT $2\n\
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
}

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
    let result_summary: Option<String> =
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
            let rows = sqlx::query(&sql)
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

            let mut q = sqlx::query(&sql);
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
            let mut jobs: Vec<JobRow> = rows
                .iter()
                .map(row_to_job_row)
                .collect::<DomainResult<_>>()?;
            sort_claimed_jobs(&mut jobs);
            Ok(jobs)
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
                let mut q = sqlx::query_scalar::<_, Uuid>(&sql);
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

    fn delete_terminal_prefetch_rows_older_than<'a>(
        &'a self,
        horizon: Duration,
    ) -> BoxFuture<'a, DomainResult<u64>> {
        let interval = duration_to_pg_interval(horizon);
        Box::pin(async move {
            tracing::debug!(?horizon, "delete_terminal_prefetch_rows_older_than");
            let res = sqlx::query(
                "DELETE FROM public.jobs \
                  WHERE kind LIKE 'prefetch%' \
                    AND status IN ('completed', 'failed') \
                    AND updated_at < now() - $1::interval",
            )
            .bind(interval)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Job", "delete_terminal_prefetch_rows_older_than"))?;
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
        // Each substring below was a token-mashing site in the bug.
        let must_contain = [
            "FROM public.jobs",
            "public.jobs\n",
            "'pending'\n",
            "ANY($1::text[])\n",
            "now())\n",
            "LIMIT $2\n",
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
        // bare-`\` bug produced. Listing them as substrings guards
        // against any future regression that drops a `\n` before a
        // continuation.
        let must_not_contain = [
            "jobsWHERE",
            "'pending'AND",
            "ANY($1::text[])AND",
            "now())ORDER",
            "FOR UPDATE SKIP LOCKEDLIMIT",
            "now()WHERE",
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
    #[ignore = "requires DATABASE_URL"]
    async fn row_to_scan_job_populates_trigger_source_cron_and_priority_10() {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
        let pool = PgPool::connect(&db_url).await.expect("connect to Postgres");

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

        sqlx::query("DELETE FROM public.jobs WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    /// Ingest path inserts with the column default `priority=0` and an
    /// explicit `trigger_source='ingest'`. The mapper must round-trip
    /// both unchanged.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn row_to_scan_job_populates_default_ingest_trigger_source_and_priority_0() {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
        let pool = PgPool::connect(&db_url).await.expect("connect to Postgres");

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

        sqlx::query("DELETE FROM public.jobs WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("cleanup");
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
    // Run with:
    //   DATABASE_URL=postgresql://... cargo test -p hort-adapters-postgres -- --ignored

    /// `PgJobsRepository::enqueue_task` inserts a row and returns a Uuid;
    /// the row exists in `jobs` with the expected columns.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL"]
    async fn enqueue_task_inserts_row_and_returns_uuid() {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
        let pool = PgPool::connect(&db_url).await.expect("connect to Postgres");
        let repo = PgJobsRepository::new(pool.clone());

        let params = serde_json::json!({"dry_run": true});
        let actor_id = Some(Uuid::new_v4());
        let outcome = repo
            .enqueue_task("noop", &params, actor_id, 0, "integration-test", None)
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

        // Clean up — remove the test row.
        sqlx::query("DELETE FROM public.jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .expect("cleanup failed");
    }

    // -----------------------------------------------------------------
    // Cascade tests against the real partial unique indexes
    // (`jobs_prefetch_unique` + `jobs_prefetch_dependencies_unique`)
    // and the retention sweep predicate. Carries `#[serial(hort_pg_db)]`
    // per ADR 0019.
    // -----------------------------------------------------------------

    use hort_domain::ports::jobs_repository::PrefetchEnqueueRow as PER;
    use serial_test::serial;

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
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

    /// Retention sweep deletes `completed` + `failed` prefetch%
    /// rows older than the horizon, leaves `pending`/`running`
    /// rows alone.
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

        // Sweep: horizon = 1 day. The two old-and-terminal rows
        // qualify; the pending + running + fresh-completed rows do
        // not.
        let deleted = repo
            .delete_terminal_prefetch_rows_older_than(Duration::from_secs(86_400))
            .await
            .expect("retention sweep");
        assert_eq!(
            deleted, 2,
            "exactly the two old-terminal rows are deleted (not pending/running, not fresh)",
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
}
