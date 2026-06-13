//! PostgreSQL adapter for [`RepoSecurityScoreRepository`] — the per-repo
//! `repo_security_scores` projection from migration 009.
//!
//! Two layers:
//!
//! 1. The trait impl ([`PgRepoSecurityScoreRepository`]) — standalone
//!    `upsert` / `find` for callers outside the lifecycle dual-write
//!    path (e.g. reconciliation tasks, the eventual REST read endpoint).
//! 2. The `apply_delta_in_tx` helper — used by
//!    [`crate::artifact_lifecycle::PgArtifactLifecycle`] to apply a
//!    [`ScoreDelta`] inside the open lifecycle transaction so the
//!    projection upsert lands atomically with the event append + the
//!    artifact state mutation.
//!
//! The underflow guard (`GREATEST(0, current + delta)`) is applied in
//! the SQL itself — the only authoritative place to enforce
//! "counts never go negative" given Postgres also serves direct
//! inserts and the migration's CHECK constraints don't cover signed
//! arithmetic.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::repo_security_score_repository::{
    RepoSecurityScore, RepoSecurityScoreRepository, ScoreDelta,
};

use crate::BoxFuture;

/// PostgreSQL adapter for the `repo_security_scores` projection.
pub struct PgRepoSecurityScoreRepository {
    pool: PgPool,
}

impl PgRepoSecurityScoreRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Convert a SQL `int4` column to a `u32`, clamping negatives at zero.
/// The column itself uses `integer NOT NULL DEFAULT 0` (signed `int4`);
/// the underflow clamp in `apply_delta_in_tx` should keep values
/// non-negative, but the converter is the second gate against a row
/// stamped by a future code path that bypasses the helper.
fn i32_to_u32_clamp_zero(v: i32) -> u32 {
    if v < 0 {
        0
    } else {
        v as u32
    }
}

/// Map a u32 count to i32 for binding — clamps at i32::MAX so absurd
/// counts don't overflow. Real artifact volume never approaches this
/// ceiling.
fn u32_to_i32_clamp(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

/// Apply a [`ScoreDelta`] to the `repo_security_scores` row for
/// `repo_id` inside the open transaction `tx`. Insert-on-missing,
/// update-on-existing semantics. Underflow clamped via
/// `GREATEST(0, current + delta)` directly in SQL.
///
/// Caller (`PgArtifactLifecycle::commit_*_with_score`) handles the
/// `delta.is_noop()` shortcut — calling this function with a noop
/// delta is harmless but generates a needless UPDATE. The function
/// itself short-circuits empty deltas to keep the no-op path quiet.
///
/// `pub` (not `pub(crate)`) so the
/// `tests/repo_security_score_repository.rs` integration test can
/// drive the helper against a live Postgres without going through the
/// full lifecycle path.
pub async fn apply_delta_in_tx(
    tx: &mut sqlx::PgConnection,
    repo_id: Uuid,
    delta: &ScoreDelta,
) -> DomainResult<()> {
    if delta.is_noop() {
        return Ok(());
    }
    let now = Utc::now();
    // The INSERT branch seeds the row from zero, then the
    // ON CONFLICT clause clamps each count at zero via GREATEST.
    // `last_scan_at` uses COALESCE on the new value so a pure
    // status-transition delta (where `delta.last_scan_at` is None)
    // preserves the existing value.
    sqlx::query(
        r#"
        INSERT INTO repo_security_scores (
            repository_id,
            quarantined_count, rejected_count, released_count,
            critical_count, high_count, medium_count, low_count,
            last_scan_at, updated_at
        ) VALUES (
            $1,
            GREATEST(0, $2),
            GREATEST(0, $3),
            GREATEST(0, $4),
            GREATEST(0, $5),
            GREATEST(0, $6),
            GREATEST(0, $7),
            GREATEST(0, $8),
            $9, $10
        )
        ON CONFLICT (repository_id) DO UPDATE SET
            quarantined_count = GREATEST(0, repo_security_scores.quarantined_count + $2),
            rejected_count    = GREATEST(0, repo_security_scores.rejected_count    + $3),
            released_count    = GREATEST(0, repo_security_scores.released_count    + $4),
            critical_count    = GREATEST(0, repo_security_scores.critical_count    + $5),
            high_count        = GREATEST(0, repo_security_scores.high_count        + $6),
            medium_count      = GREATEST(0, repo_security_scores.medium_count      + $7),
            low_count         = GREATEST(0, repo_security_scores.low_count         + $8),
            last_scan_at      = COALESCE($9, repo_security_scores.last_scan_at),
            updated_at        = $10
        "#,
    )
    .bind(repo_id)
    .bind(delta.quarantined_delta)
    .bind(delta.rejected_delta)
    .bind(delta.released_delta)
    .bind(delta.critical_delta)
    .bind(delta.high_delta)
    .bind(delta.medium_delta)
    .bind(delta.low_delta)
    .bind(delta.last_scan_at)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| DomainError::Invariant(format!("repo_security_scores apply_delta_in_tx: {e}")))?;
    Ok(())
}

impl RepoSecurityScoreRepository for PgRepoSecurityScoreRepository {
    fn upsert<'a>(&'a self, score: &'a RepoSecurityScore) -> BoxFuture<'a, DomainResult<()>> {
        let row = score.clone();
        Box::pin(async move {
            sqlx::query(
                r#"
                INSERT INTO repo_security_scores (
                    repository_id,
                    quarantined_count, rejected_count, released_count,
                    critical_count, high_count, medium_count, low_count,
                    last_scan_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (repository_id) DO UPDATE SET
                    quarantined_count = EXCLUDED.quarantined_count,
                    rejected_count    = EXCLUDED.rejected_count,
                    released_count    = EXCLUDED.released_count,
                    critical_count    = EXCLUDED.critical_count,
                    high_count        = EXCLUDED.high_count,
                    medium_count      = EXCLUDED.medium_count,
                    low_count         = EXCLUDED.low_count,
                    last_scan_at      = EXCLUDED.last_scan_at,
                    updated_at        = EXCLUDED.updated_at
                "#,
            )
            .bind(row.repository_id)
            .bind(u32_to_i32_clamp(row.quarantined_count))
            .bind(u32_to_i32_clamp(row.rejected_count))
            .bind(u32_to_i32_clamp(row.released_count))
            .bind(u32_to_i32_clamp(row.critical_count))
            .bind(u32_to_i32_clamp(row.high_count))
            .bind(u32_to_i32_clamp(row.medium_count))
            .bind(u32_to_i32_clamp(row.low_count))
            .bind(row.last_scan_at)
            .bind(row.updated_at)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::Invariant(format!("repo_security_scores upsert: {e}")))?;
            Ok(())
        })
    }

    fn find(&self, repo_id: Uuid) -> BoxFuture<'_, DomainResult<Option<RepoSecurityScore>>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, RowShape>(
                r#"
                SELECT
                    repository_id,
                    quarantined_count, rejected_count, released_count,
                    critical_count, high_count, medium_count, low_count,
                    last_scan_at, updated_at
                FROM repo_security_scores
                WHERE repository_id = $1
                "#,
            )
            .bind(repo_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| DomainError::Invariant(format!("repo_security_scores find: {e}")))?;
            Ok(row.map(RowShape::into_domain))
        })
    }
}

/// Internal sqlx FromRow shape — the migration uses `int4` (signed)
/// columns, so we read as `i32` and clamp to `u32` at the boundary.
#[derive(sqlx::FromRow)]
struct RowShape {
    repository_id: Uuid,
    quarantined_count: i32,
    rejected_count: i32,
    released_count: i32,
    critical_count: i32,
    high_count: i32,
    medium_count: i32,
    low_count: i32,
    last_scan_at: Option<chrono::DateTime<Utc>>,
    updated_at: chrono::DateTime<Utc>,
}

impl RowShape {
    fn into_domain(self) -> RepoSecurityScore {
        RepoSecurityScore {
            repository_id: self.repository_id,
            quarantined_count: i32_to_u32_clamp_zero(self.quarantined_count),
            rejected_count: i32_to_u32_clamp_zero(self.rejected_count),
            released_count: i32_to_u32_clamp_zero(self.released_count),
            critical_count: i32_to_u32_clamp_zero(self.critical_count),
            high_count: i32_to_u32_clamp_zero(self.high_count),
            medium_count: i32_to_u32_clamp_zero(self.medium_count),
            low_count: i32_to_u32_clamp_zero(self.low_count),
            last_scan_at: self.last_scan_at,
            updated_at: self.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that the adapter implements the port.
    #[test]
    fn pg_adapter_implements_port() {
        fn assert_impl<T: RepoSecurityScoreRepository>() {}
        assert_impl::<PgRepoSecurityScoreRepository>();
    }

    #[test]
    fn i32_to_u32_clamp_zero_negative_clamps() {
        assert_eq!(i32_to_u32_clamp_zero(-5), 0);
        assert_eq!(i32_to_u32_clamp_zero(0), 0);
        assert_eq!(i32_to_u32_clamp_zero(7), 7);
    }

    #[test]
    fn u32_to_i32_clamp_max_clamps() {
        assert_eq!(u32_to_i32_clamp(0), 0);
        assert_eq!(u32_to_i32_clamp(7), 7);
        assert_eq!(u32_to_i32_clamp(u32::MAX), i32::MAX);
    }
}
