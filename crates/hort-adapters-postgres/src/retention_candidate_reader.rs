//! PostgreSQL adapter for [`RetentionCandidateReader`] (ADR 0020).
//!
//! Enumerates non-protected artifacts and resolves each one's
//! repo-scoped rescan interval (freshness-window input)
//! via the repo→policy chain — the **identical**
//! `JOIN LATERAL policy_projections` the
//! [`rescan_candidates`](crate::rescan_candidates) adapter uses, with
//! two deliberate deviations from the rescan adapter:
//!
//! 1. **LEFT** join, not INNER: an artifact with no resolved scan
//!    policy yields `resolved_rescan_interval_hours = None` (→ default
//!    24 h) rather than being dropped — age-based retention applies
//!    even without a scan policy.
//! 2. The protected-status filter is `quarantine_status NOT IN
//!    ('quarantined','rejected','scan_indeterminate')` (the GC-protected
//!    set: `none` / `released` are retention-eligible) — broader than
//!    the rescan adapter's `= 'released'`.
//!
//! The query additionally `JOIN`s `repositories r ON r.id =
//! a.repository_id` to select `r.format` (aliased `repo_format`) — the
//! per-artifact [`RepositoryFormat`] the `RetentionScope::Format`
//! gate needs (`Artifact` itself has no `format` field). This is an
//! INNER join: every artifact's `repository_id` is a FK into
//! `repositories`, so it never drops a row. Still a **single query**:
//! no extra round-trip, no N+1, no scope SQL pre-filter (scope
//! matching stays in `RetentionUseCase::evaluate_one` per the port
//! docstring).
//!
//! Keyset-paginated by `artifacts.id` (`after` cursor + `ORDER BY a.id
//! LIMIT $batch`): retention has no in-flight-job dedup to naturally
//! bound re-visits, so the handler advances the cursor across pages
//! (the daily cron drains any backlog, identical posture to
//! cron-rescan's single-shot cap).

use chrono::{DateTime, Utc};
use sqlx::{postgres::PgRow, FromRow, PgPool, Row};
use uuid::Uuid;

use hort_domain::entities::artifact::Artifact;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::retention_candidate_reader::{
    RetentionCandidateReader, RetentionCandidateRow,
};

use crate::mappers::ArtifactRow;
use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL adapter for the retention candidate-enumeration query.
pub struct PgRetentionCandidateReader {
    pool: PgPool,
}

impl PgRetentionCandidateReader {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn decode_candidate(row: &PgRow) -> DomainResult<RetentionCandidateRow> {
    // `ArtifactRow` is `FromRow`; it reads only its own named columns
    // from the wider joined result set.
    let ar = ArtifactRow::from_row(row).map_err(|e| {
        tracing::warn!(error = %e, "retention_candidate artifact row decode failed");
        DomainError::Invariant(format!("retention_candidate artifact row decode: {e}"))
    })?;
    let artifact = Artifact::try_from(ar)?;
    // `repositories.format text` → `RepositoryFormat` via the existing
    // infallible `FromStr` (unknown values fold to `Other(s)`); same
    // mapping idiom the `RepositoryRow` → `Repository` mapper uses
    // (`mappers.rs`: `.parse().unwrap_or(RepositoryFormat::Generic)`).
    let repo_format_raw: String = row.try_get("repo_format").map_err(|e| {
        tracing::warn!(error = %e, "retention_candidate repo format decode failed");
        DomainError::Invariant(format!("retention_candidate repo_format decode: {e}"))
    })?;
    let format: RepositoryFormat = repo_format_raw.parse().unwrap_or(RepositoryFormat::Generic);
    let resolved_rescan_interval_hours: Option<i32> =
        row.try_get("resolved_rescan_interval_hours").map_err(|e| {
            tracing::warn!(error = %e, "retention_candidate rescan-interval decode failed");
            DomainError::Invariant(format!(
                "retention_candidate resolved_rescan_interval_hours decode: {e}"
            ))
        })?;
    Ok(RetentionCandidateRow {
        artifact,
        format,
        resolved_rescan_interval_hours: resolved_rescan_interval_hours.map(i64::from),
    })
}

impl RetentionCandidateReader for PgRetentionCandidateReader {
    fn list_candidates<'a>(
        &'a self,
        batch_size: u32,
        after: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<Vec<RetentionCandidateRow>>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "retention_candidate",
                batch_size,
                has_cursor = after.is_some(),
                %now,
                "list_candidates"
            );
            // The LATERAL picks the resolved policy per artifact: a
            // repo-scoped non-archived policy if one exists, else a
            // non-archived Global. LEFT JOIN so a no-policy artifact
            // is kept with `resolved_rescan_interval_hours = NULL`
            // (→ default 24h) — NOT dropped (the rescan adapter's
            // INNER-join behaviour is wrong for age-based retention).
            //
            // `$3::uuid` keyset cursor: when NULL, no lower bound
            // (first page); otherwise `a.id > $3`. The `now`
            // parameter is bound for caller-pinned time coherence
            // even though the protected-status filter does not
            // consult it — kept in the signature/SQL so a future age
            // pre-filter has a pinned `now` available without a
            // signature change.
            let sql = r#"
                SELECT a.id, a.repository_id, a.name, a.name_as_published,
                       a.version, a.path, a.size_bytes,
                       a.checksum_sha256, a.checksum_sha1, a.checksum_md5,
                       a.content_type, a.storage_key,
                       a.quarantine_status, a.quarantine_window_start,
                       a.upstream_published_at,
                       a.uploaded_by, a.is_deleted,
                       a.created_at, a.updated_at,
                       r.format AS repo_format,
                       p.rescan_interval_hours AS resolved_rescan_interval_hours
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
                LEFT JOIN LATERAL (
                    SELECT pp.rescan_interval_hours
                    FROM policy_projections pp
                    WHERE pp.archived = false
                      AND (
                            (pp.scope ? 'Repository'
                              AND (pp.scope->>'Repository')::uuid = a.repository_id)
                         OR (pp.scope ? 'Global'
                              AND NOT EXISTS (
                                SELECT 1 FROM policy_projections pp2
                                WHERE pp2.archived = false
                                  AND pp2.scope ? 'Repository'
                                  AND (pp2.scope->>'Repository')::uuid = a.repository_id
                              ))
                          )
                    ORDER BY (pp.scope ? 'Repository') DESC
                    LIMIT 1
                ) p ON TRUE
                WHERE a.is_deleted = false
                  AND a.quarantine_status NOT IN
                      ('quarantined', 'rejected', 'scan_indeterminate')
                  AND ($3::uuid IS NULL OR a.id > $3)
                ORDER BY a.id
                LIMIT $1
            "#;
            let rows = sqlx::query(sql)
                .bind(i64::from(batch_size))
                .bind(now)
                .bind(after)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "RetentionCandidate", "list_candidates"))?;
            rows.iter().map(decode_candidate).collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    /// Empty-table query compiles + runs (also exercises the keyset
    /// cursor binding path).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_candidates_empty_db_returns_empty() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let reader = PgRetentionCandidateReader::new(pool);
        // No cursor.
        let none = reader
            .list_candidates(1000, None, Utc::now())
            .await
            .expect("query runs");
        // With a cursor (exercises the `$3 IS NOT NULL` branch).
        let after = reader
            .list_candidates(1000, Some(Uuid::new_v4()), Utc::now())
            .await
            .expect("query runs with cursor");
        // The shared test DB may contain rows from other suites; the
        // only invariant we can assert without seeding is that the
        // protected-status filter never yields a protected artifact.
        for c in none.iter().chain(after.iter()) {
            assert!(
                !matches!(
                    c.artifact.quarantine_status,
                    hort_domain::entities::artifact::QuarantineStatus::Quarantined
                        | hort_domain::entities::artifact::QuarantineStatus::Rejected
                        | hort_domain::entities::artifact::QuarantineStatus::ScanIndeterminate
                ),
                "protected artifact leaked into retention candidates"
            );
        }
    }
}
