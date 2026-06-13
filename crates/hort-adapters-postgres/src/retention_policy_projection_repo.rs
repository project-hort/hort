//! PostgreSQL adapter for [`RetentionPolicyProjectionRepository`]
//! (ADR 0020).
//!
//! Backed by `retention_policy_projections` (`005_policy.sql`).
//! Reads are covered by the PK + the `active_name` partial index;
//! writes are `ON CONFLICT (policy_id) DO UPDATE` upserts paired with
//! `ExpectedVersion::Exact` on the event-store side so a concurrent
//! write between projection-read and event-append surfaces as
//! `ConcurrentModification` — the same shape as
//! `PgPolicyProjectionRepository`.
//!
//! `PolicyPredicate` / `RetentionScope` round-trip through JSONB via
//! serde (both are `Serialize + Deserialize` in `hort-domain`). Decode
//! failures surface as [`DomainError::Invariant`] (the table is
//! gitops-managed; corrupt JSON is a bug, not a request error).
//!
//! Tracing per CLAUDE.md observability rules: every read logs at
//! `debug!` with `entity = "retention_policy"` and the lookup key;
//! unexpected sqlx errors log at `warn!`. Never SQL text or bind
//! values.

use chrono::{DateTime, Utc};
use sqlx::{postgres::PgRow, PgPool, Row};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::retention_policy_projection_repository::{
    RetentionPolicyProjectionRepository, RetentionPolicyRow,
};
use hort_domain::retention::{PolicyPredicate, RetentionPolicy, RetentionScope};

use crate::BoxFuture;

/// PostgreSQL implementation of [`RetentionPolicyProjectionRepository`].
pub struct PgRetentionPolicyProjectionRepository {
    pool: PgPool,
}

impl PgRetentionPolicyProjectionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const SELECT_COLS: &str = r#"
    SELECT policy_id, name, predicate, scope, archived, stream_version,
           last_evaluated_at, last_matched_count, last_expired_count,
           created_at, updated_at
    FROM retention_policy_projections
"#;

fn row_to_row(row: &PgRow) -> DomainResult<RetentionPolicyRow> {
    let policy_id: Uuid = row.try_get("policy_id").map_err(|e| map_row_err(&e))?;
    let name: String = row.try_get("name").map_err(|e| map_row_err(&e))?;
    let predicate_json: serde_json::Value =
        row.try_get("predicate").map_err(|e| map_row_err(&e))?;
    let predicate: PolicyPredicate = serde_json::from_value(predicate_json).map_err(|e| {
        DomainError::Invariant(format!(
            "retention_policy_projections.predicate decode for {policy_id}: {e}"
        ))
    })?;
    let scope_json: serde_json::Value = row.try_get("scope").map_err(|e| map_row_err(&e))?;
    let scope: RetentionScope = serde_json::from_value(scope_json).map_err(|e| {
        DomainError::Invariant(format!(
            "retention_policy_projections.scope decode for {policy_id}: {e}"
        ))
    })?;
    let archived: bool = row.try_get("archived").map_err(|e| map_row_err(&e))?;
    let stream_version_i64: i64 = row.try_get("stream_version").map_err(|e| map_row_err(&e))?;
    let stream_version = u64::try_from(stream_version_i64).map_err(|_| {
        DomainError::Invariant(format!(
            "retention_policy_projections.stream_version negative for {policy_id}: \
             {stream_version_i64}"
        ))
    })?;
    let last_evaluated_at: Option<DateTime<Utc>> = row
        .try_get("last_evaluated_at")
        .map_err(|e| map_row_err(&e))?;
    let last_matched_count_i32: i32 = row
        .try_get("last_matched_count")
        .map_err(|e| map_row_err(&e))?;
    let last_expired_count_i32: i32 = row
        .try_get("last_expired_count")
        .map_err(|e| map_row_err(&e))?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(|e| map_row_err(&e))?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(|e| map_row_err(&e))?;
    Ok(RetentionPolicyRow {
        policy_id,
        name,
        predicate,
        scope,
        archived,
        stream_version,
        last_evaluated_at,
        last_matched_count: last_matched_count_i32.max(0) as u32,
        last_expired_count: last_expired_count_i32.max(0) as u32,
        created_at,
        updated_at,
    })
}

fn map_row_err(e: &sqlx::Error) -> DomainError {
    tracing::warn!(entity = "retention_policy", error = %e, "row decode failed");
    DomainError::Invariant(format!("retention_policy_projections row decode: {e}"))
}

fn map_query_err(e: &sqlx::Error, op: &'static str) -> DomainError {
    tracing::warn!(entity = "retention_policy", op, error = %e, "query failed");
    DomainError::Invariant(format!("retention_policy_projections {op}: {e}"))
}

impl RetentionPolicyProjectionRepository for PgRetentionPolicyProjectionRepository {
    fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicy>>> {
        Box::pin(async move {
            tracing::debug!(entity = "retention_policy", "list_active");
            let sql = format!("{SELECT_COLS} WHERE archived = false ORDER BY name");
            let rows = sqlx::query(&sql)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_query_err(&e, "list_active"))?;
            rows.iter()
                .map(|r| row_to_row(r).map(RetentionPolicyRow::into_policy))
                .collect()
        })
    }

    fn find_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>> {
        let name = name.to_owned();
        Box::pin(async move {
            tracing::debug!(entity = "retention_policy", lookup_key = %name, "find_by_name");
            let sql = format!("{SELECT_COLS} WHERE name = $1 AND archived = false");
            let row = sqlx::query(&sql)
                .bind(&name)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_query_err(&e, "find_by_name"))?;
            row.map(|r| row_to_row(&r)).transpose()
        })
    }

    fn find_by_name_including_archived(
        &self,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>> {
        let name = name.to_owned();
        Box::pin(async move {
            tracing::debug!(
                entity = "retention_policy",
                lookup_key = %name,
                "find_by_name_including_archived"
            );
            // Order: prefer the active row if both an active and an
            // archived row of this name exist (B1's terminal-archive
            // model means a fresh policy_id is minted for a
            // re-declared archived name — the old archived row stays
            // as audit history; the apply pipeline wants the active
            // one first when present).
            let sql = format!(
                "{SELECT_COLS} WHERE name = $1 ORDER BY archived ASC, created_at DESC LIMIT 1"
            );
            let row = sqlx::query(&sql)
                .bind(&name)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_query_err(&e, "find_by_name_including_archived"))?;
            row.map(|r| row_to_row(&r)).transpose()
        })
    }

    fn list_active_rows(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicyRow>>> {
        Box::pin(async move {
            tracing::debug!(entity = "retention_policy", "list_active_rows");
            let sql = format!("{SELECT_COLS} WHERE archived = false ORDER BY name");
            let rows = sqlx::query(&sql)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_query_err(&e, "list_active_rows"))?;
            rows.iter().map(row_to_row).collect()
        })
    }

    fn upsert(&self, row: &RetentionPolicyRow) -> BoxFuture<'_, DomainResult<()>> {
        let policy_id = row.policy_id;
        let name = row.name.clone();
        let predicate = match serde_json::to_value(&row.predicate) {
            Ok(v) => v,
            Err(e) => {
                return Box::pin(async move {
                    Err(DomainError::Invariant(format!(
                        "PolicyPredicate serialise: {e}"
                    )))
                })
            }
        };
        let scope = match serde_json::to_value(&row.scope) {
            Ok(v) => v,
            Err(e) => {
                return Box::pin(async move {
                    Err(DomainError::Invariant(format!(
                        "RetentionScope serialise: {e}"
                    )))
                })
            }
        };
        let archived = row.archived;
        let raw_version = row.stream_version;
        let Ok(stream_version) = i64::try_from(raw_version) else {
            return Box::pin(async move {
                Err(DomainError::Invariant(format!(
                    "stream_version exceeds i64::MAX: {raw_version}"
                )))
            });
        };
        let last_evaluated_at = row.last_evaluated_at;
        let last_matched_count = i32::try_from(row.last_matched_count).unwrap_or(i32::MAX);
        let last_expired_count = i32::try_from(row.last_expired_count).unwrap_or(i32::MAX);
        let created_at = row.created_at;
        let updated_at = row.updated_at;

        Box::pin(async move {
            tracing::debug!(entity = "retention_policy", lookup_key = %policy_id, "upsert");
            sqlx::query(
                r#"INSERT INTO retention_policy_projections (
                       policy_id, name, predicate, scope, archived,
                       stream_version, last_evaluated_at,
                       last_matched_count, last_expired_count,
                       created_at, updated_at
                   ) VALUES (
                       $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
                   )
                   ON CONFLICT (policy_id) DO UPDATE SET
                       name               = EXCLUDED.name,
                       predicate          = EXCLUDED.predicate,
                       scope              = EXCLUDED.scope,
                       archived           = EXCLUDED.archived,
                       stream_version     = EXCLUDED.stream_version,
                       last_evaluated_at  = EXCLUDED.last_evaluated_at,
                       last_matched_count = EXCLUDED.last_matched_count,
                       last_expired_count = EXCLUDED.last_expired_count,
                       updated_at         = EXCLUDED.updated_at"#,
            )
            .bind(policy_id)
            .bind(&name)
            .bind(&predicate)
            .bind(&scope)
            .bind(archived)
            .bind(stream_version)
            .bind(last_evaluated_at)
            .bind(last_matched_count)
            .bind(last_expired_count)
            .bind(created_at)
            .bind(updated_at)
            .execute(&self.pool)
            .await
            .map_err(|e| map_query_err(&e, "upsert"))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::retention::BooleanOp;
    use serial_test::serial;
    use std::env;

    #[test]
    fn map_query_err_wraps_invariant() {
        let err = map_query_err(&sqlx::Error::PoolClosed, "list_active");
        match err {
            DomainError::Invariant(msg) => assert!(msg.contains("list_active"), "msg = {msg}"),
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    #[test]
    fn map_row_err_wraps_invariant() {
        assert!(matches!(
            map_row_err(&sqlx::Error::PoolClosed),
            DomainError::Invariant(_)
        ));
    }

    // ---- DB-backed integration tests. Skipped when DATABASE_URL is
    // unset (the established `hort-adapters-postgres` convention —
    // `policy_projection_repo.rs` / `repository_upstream_mapping_repo.rs`).
    // `#[serial(hort_pg_db)]` is mandatory (the `ed79360a` flake rule).

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    /// The canonical B1 fixture
    /// `Composite(And,[HasFindingAboveSeverity(High), HasFixAvailable,
    /// HasFindingDetectedFor(7d)])` — the exact replay fixture B1's
    /// acceptance bullet exercises in-domain. Persists + reloads
    /// byte-equal through the projection adapter.
    fn canonical_fixture(policy_id: Uuid, name: &str, version: u64) -> RetentionPolicyRow {
        use hort_domain::entities::scan_policy::SeverityThreshold;
        let now = Utc::now();
        RetentionPolicyRow {
            policy_id,
            name: name.into(),
            predicate: PolicyPredicate::Composite(
                BooleanOp::And,
                vec![
                    PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
                    PolicyPredicate::HasFixAvailable,
                    PolicyPredicate::HasFindingDetectedFor(7 * 24 * 3600),
                ],
            ),
            scope: RetentionScope::IngestSource(hort_domain::events::IngestSource::Proxied),
            archived: false,
            stream_version: version,
            last_evaluated_at: None,
            last_matched_count: 0,
            last_expired_count: 0,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_then_list_active_round_trips_canonical_fixture_byte_equal() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgRetentionPolicyProjectionRepository::new(pool);
        let id = Uuid::new_v4();
        let name = format!("retain-{}", id.simple());
        let row = canonical_fixture(id, &name, 2);
        repo.upsert(&row).await.expect("upsert");

        let actives = repo.list_active().await.expect("list_active");
        let got = actives
            .iter()
            .find(|p| p.id == id)
            .expect("canonical fixture present in list_active");
        // Byte-equal predicate + scope after the JSONB serde round-trip.
        assert_eq!(got.predicate, row.predicate);
        assert_eq!(got.scope, row.scope);
        assert_eq!(got.name, row.name);
        assert_eq!(got.stream_version, 2);
        assert!(!got.archived);

        // find_by_name returns the active row.
        let found = repo
            .find_by_name(&name)
            .await
            .expect("find_by_name")
            .expect("active row present");
        assert_eq!(found.policy_id, id);
        assert_eq!(found.predicate, row.predicate);
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn upsert_advances_stream_version_and_archived_excluded_from_active() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgRetentionPolicyProjectionRepository::new(pool);
        let id = Uuid::new_v4();
        let name = format!("retain-arch-{}", id.simple());
        let mut row = canonical_fixture(id, &name, 0);
        repo.upsert(&row).await.expect("create");

        // Archive: bump version + archived=true. list_active /
        // find_by_name must now exclude it; find_by_name_including_archived
        // still returns it.
        row.archived = true;
        row.stream_version = 1;
        repo.upsert(&row).await.expect("archive upsert");

        assert!(
            repo.list_active()
                .await
                .expect("list_active")
                .iter()
                .all(|p| p.id != id),
            "archived row must not appear in list_active"
        );
        assert!(
            repo.find_by_name(&name)
                .await
                .expect("find_by_name")
                .is_none(),
            "find_by_name excludes archived"
        );
        let arch = repo
            .find_by_name_including_archived(&name)
            .await
            .expect("find_by_name_including_archived")
            .expect("archived row still findable");
        assert!(arch.archived);
        assert_eq!(arch.stream_version, 1);
    }
}
