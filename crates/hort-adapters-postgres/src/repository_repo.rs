use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use hort_domain::entities::repository::Repository;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::types::{Page, PageRequest};

use crate::mappers::RepositoryRow;
use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`RepositoryRepository`].
pub struct PgRepositoryRepository {
    pool: PgPool,
}

impl PgRepositoryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// SQL fragment for selecting all repository columns with enum casts.
///
/// `managed_by` / `managed_by_digest` are appended next so the column
/// order matches `RepositoryRow`'s field order. The curation-rule-name
/// lookup is folded into the same SELECT via a correlated `ARRAY_AGG`
/// subquery — every read path returns the row + its attached rule
/// names in a single round-trip. The previous
/// `attach_rule_names` helper, which fired one extra junction query
/// per row, is gone. The subquery sorts by `cr.name` to preserve the
/// stable ordering callers depended on; an empty `COALESCE` fallback
/// keeps the column non-NULL for repositories with no rules attached
/// so sqlx's `Vec<String>` decode never sees a SQL NULL. The decoded
/// `RepositoryRowWithRules` (this file) flattens `RepositoryRow` and
/// attaches the names slice without modifying the shared row mapper.
const SELECT_COLS: &str = r#"
    id, key, name, description,
    format::TEXT as format,
    repo_type::TEXT as repo_type,
    storage_backend, storage_path, upstream_url,
    index_upstream_url,
    is_public, download_audit_enabled, index_mode,
    prefetch_enabled, prefetch_triggers, prefetch_depth,
    prefetch_transitive_depth, prefetch_max_age_days,
    prefetch_max_descendants,
    quota_bytes,
    replication_priority::TEXT as replication_priority,
    promotion_target_id, promotion_policy_id,
    created_at, updated_at,
    managed_by, managed_by_digest,
    COALESCE((
        SELECT ARRAY_AGG(cr.name ORDER BY cr.name)
        FROM repository_curation_rules rcr
        JOIN curation_rules cr ON cr.id = rcr.curation_rule_id
        WHERE rcr.repository_id = repositories.id
    ), ARRAY[]::TEXT[]) AS curation_rule_names
"#;

/// Row decoded from every repository read path: the existing
/// [`RepositoryRow`] flattened in via `#[sqlx(flatten)]`, plus the
/// `curation_rule_names` array materialised by the correlated
/// `ARRAY_AGG` subquery in [`SELECT_COLS`]. Kept local to this file so
/// the shared row mapper stays a 1:1 projection of the `repositories`
/// table — the junction-rule slice is a query-side concern, not part
/// of the row shape itself.
#[derive(Debug, FromRow)]
struct RepositoryRowWithRules {
    #[sqlx(flatten)]
    row: RepositoryRow,
    curation_rule_names: Vec<String>,
}

impl From<RepositoryRowWithRules> for Repository {
    fn from(value: RepositoryRowWithRules) -> Self {
        let mut repo: Repository = value.row.into();
        repo.curation_rule_names = value.curation_rule_names;
        repo
    }
}

impl RepositoryRepository for PgRepositoryRepository {
    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Repository>> {
        Box::pin(async move {
            tracing::debug!(entity = "Repository", %id, "find_by_id");
            let sql = format!("SELECT {SELECT_COLS} FROM repositories WHERE id = $1");
            let row: RepositoryRowWithRules = sqlx::query_as(&sql)
                .bind(id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Repository", &id.to_string()))?;
            Ok(row.into())
        })
    }

    fn find_by_key(&self, key: &str) -> BoxFuture<'_, DomainResult<Repository>> {
        let key = key.to_string();
        Box::pin(async move {
            tracing::debug!(entity = "Repository", key = %key, "find_by_key");
            let sql = format!("SELECT {SELECT_COLS} FROM repositories WHERE key = $1");
            let row: RepositoryRowWithRules = sqlx::query_as(&sql)
                .bind(&key)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Repository", &key))?;
            Ok(row.into())
        })
    }

    fn list(
        &self,
        page: PageRequest,
        search: Option<&str>,
    ) -> BoxFuture<'_, DomainResult<Page<Repository>>> {
        let search = search.map(|s| format!("%{}%", crate::escape_like_pattern(&s.to_lowercase())));
        let offset = page.offset as i64;
        let limit = page.limit as i64;
        Box::pin(async move {
            tracing::debug!(entity = "Repository", "list");
            let sql = format!(
                r#"SELECT {SELECT_COLS}
                   FROM repositories
                   WHERE ($1::TEXT IS NULL
                          OR LOWER(key) LIKE $1 ESCAPE '\'
                          OR LOWER(name) LIKE $1 ESCAPE '\'
                          OR LOWER(COALESCE(description, '')) LIKE $1 ESCAPE '\')
                   ORDER BY name
                   OFFSET $2 LIMIT $3"#
            );
            let rows: Vec<RepositoryRowWithRules> = sqlx::query_as(&sql)
                .bind(&search)
                .bind(offset)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Repository", "list"))?;

            let count_sql = r#"
                SELECT COUNT(*)
                FROM repositories
                WHERE ($1::TEXT IS NULL
                       OR LOWER(key) LIKE $1 ESCAPE '\'
                       OR LOWER(name) LIKE $1 ESCAPE '\'
                       OR LOWER(COALESCE(description, '')) LIKE $1 ESCAPE '\')
            "#;
            let total: Option<i64> = sqlx::query_scalar(count_sql)
                .bind(&search)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Repository", "count"))?;
            let total = total.unwrap_or(0);

            let items: Vec<Repository> = rows.into_iter().map(Into::into).collect();

            Ok(Page {
                items,
                total: total as u64,
            })
        })
    }

    fn save(&self, repository: &Repository) -> BoxFuture<'_, DomainResult<()>> {
        let repo = repository.clone();
        Box::pin(async move {
            tracing::debug!(entity = "Repository", key = %repo.key, "save");
            let format_str = repo.format.to_string();
            let repo_type_str = repo.repo_type.to_string();
            let replication_str = repo.replication_priority.to_string();

            let (promotion_target_id, promotion_policy_id) = match &repo.promotion {
                Some(p) => (Some(p.target_id), p.policy_id),
                None => (None, None),
            };

            let index_mode_str = repo.index_mode.to_string();
            // Bind the prefetch columns. The triggers list is
            // `Option<Vec<String>>` — `None` writes SQL NULL (the
            // canonical "no triggers" representation), `Some(_)` writes
            // a `text[]`. Knob columns are nullable but the domain holds
            // concrete `u32` values; we always write the current values
            // so a re-apply reflects the in-effect configuration on disk
            // rather than re-resolving against a future
            // `PrefetchPolicy::default()` drift.
            let prefetch_triggers_db: Option<Vec<String>> =
                if repo.prefetch_policy.triggers.is_empty() {
                    None
                } else {
                    Some(
                        repo.prefetch_policy
                            .triggers
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                    )
                };
            let prefetch_depth_db: i32 = repo.prefetch_policy.depth as i32;
            let prefetch_transitive_depth_db: i32 = repo.prefetch_policy.transitive_depth as i32;
            let prefetch_max_age_db: Option<i32> =
                repo.prefetch_policy.max_age_days.map(|v| v as i32);
            // Narrow `u32 → i32`. The hort-config validator caps
            // operator-set values at 100_000 (well below i32::MAX) so
            // the `as i32` cast is total in practice; an out-of-band
            // write that overflows lands as a negative which the mapper's
            // defensive `try_from` then folds back to the in-code default
            // on read (mirrors the depth/transitive_depth discipline).
            let prefetch_max_descendants_db: i32 = repo.prefetch_policy.max_descendants as i32;
            sqlx::query(
                r#"
                INSERT INTO repositories (
                    id, key, name, description,
                    format, repo_type,
                    storage_backend, storage_path, upstream_url,
                    index_upstream_url,
                    is_public, download_audit_enabled, index_mode,
                    prefetch_enabled, prefetch_triggers, prefetch_depth,
                    prefetch_transitive_depth, prefetch_max_age_days,
                    prefetch_max_descendants,
                    quota_bytes,
                    replication_priority,
                    promotion_target_id, promotion_policy_id,
                    created_at, updated_at
                )
                VALUES (
                    $1, $2, $3, $4,
                    $5::repository_format, $6::repository_type,
                    $7, $8, $9,
                    $10,
                    $11, $12, $13,
                    $14, $15, $16,
                    $17, $18,
                    $19,
                    $20,
                    $21::replication_priority,
                    $22, $23,
                    $24, $25
                )
                ON CONFLICT (id) DO UPDATE SET
                    key = EXCLUDED.key,
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    format = EXCLUDED.format,
                    repo_type = EXCLUDED.repo_type,
                    storage_backend = EXCLUDED.storage_backend,
                    storage_path = EXCLUDED.storage_path,
                    upstream_url = EXCLUDED.upstream_url,
                    index_upstream_url = EXCLUDED.index_upstream_url,
                    is_public = EXCLUDED.is_public,
                    download_audit_enabled = EXCLUDED.download_audit_enabled,
                    index_mode = EXCLUDED.index_mode,
                    prefetch_enabled = EXCLUDED.prefetch_enabled,
                    prefetch_triggers = EXCLUDED.prefetch_triggers,
                    prefetch_depth = EXCLUDED.prefetch_depth,
                    prefetch_transitive_depth = EXCLUDED.prefetch_transitive_depth,
                    prefetch_max_age_days = EXCLUDED.prefetch_max_age_days,
                    prefetch_max_descendants = EXCLUDED.prefetch_max_descendants,
                    quota_bytes = EXCLUDED.quota_bytes,
                    replication_priority = EXCLUDED.replication_priority,
                    promotion_target_id = EXCLUDED.promotion_target_id,
                    promotion_policy_id = EXCLUDED.promotion_policy_id,
                    updated_at = EXCLUDED.updated_at
                "#,
            )
            .bind(repo.id)
            .bind(&repo.key)
            .bind(&repo.name)
            .bind(&repo.description)
            .bind(&format_str)
            .bind(&repo_type_str)
            .bind(&repo.storage_backend)
            .bind(&repo.storage_path)
            .bind(&repo.upstream_url)
            .bind(&repo.index_upstream_url)
            .bind(repo.is_public)
            .bind(repo.download_audit_enabled)
            .bind(&index_mode_str)
            .bind(repo.prefetch_policy.enabled)
            .bind(&prefetch_triggers_db)
            .bind(prefetch_depth_db)
            .bind(prefetch_transitive_depth_db)
            .bind(prefetch_max_age_db)
            .bind(prefetch_max_descendants_db)
            .bind(repo.quota_bytes)
            .bind(&replication_str)
            .bind(promotion_target_id)
            .bind(promotion_policy_id)
            .bind(repo.created_at)
            .bind(repo.updated_at)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Repository", &repo.key))?;

            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(entity = "Repository", %id, "delete");
            let result = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Repository", &id.to_string()))?;

            if result.rows_affected() == 0 {
                return Err(DomainError::NotFound {
                    entity: "Repository",
                    id: id.to_string(),
                });
            }
            Ok(())
        })
    }

    fn get_virtual_members(
        &self,
        virtual_repo_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<Repository>>> {
        Box::pin(async move {
            tracing::debug!(entity = "Repository", %virtual_repo_id, "get_virtual_members");
            let sql = format!(
                r#"SELECT {SELECT_COLS}
                   FROM repositories
                   WHERE id IN (
                       SELECT member_repo_id
                       FROM virtual_repo_members
                       WHERE virtual_repo_id = $1
                   )
                   ORDER BY (
                       SELECT priority FROM virtual_repo_members
                       WHERE virtual_repo_id = $1 AND member_repo_id = repositories.id
                   )"#
            );
            let rows: Vec<RepositoryRowWithRules> = sqlx::query_as(&sql)
                .bind(virtual_repo_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "VirtualRepoMember", &virtual_repo_id.to_string())
                })?;
            let items: Vec<Repository> = rows.into_iter().map(Into::into).collect();
            Ok(items)
        })
    }

    fn add_virtual_member(
        &self,
        virtual_repo_id: Uuid,
        member_repo_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(entity = "Repository", %virtual_repo_id, %member_repo_id, "add_virtual_member");
            sqlx::query(
                r#"INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority)
                   VALUES ($1, $2, (
                       SELECT COALESCE(MAX(priority), 0) + 1
                       FROM virtual_repo_members
                       WHERE virtual_repo_id = $1
                   ))
                   ON CONFLICT (virtual_repo_id, member_repo_id) DO NOTHING"#,
            )
            .bind(virtual_repo_id)
            .bind(member_repo_id)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "VirtualRepoMember", &member_repo_id.to_string()))?;
            Ok(())
        })
    }

    fn remove_virtual_member(
        &self,
        virtual_repo_id: Uuid,
        member_repo_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(entity = "Repository", %virtual_repo_id, %member_repo_id, "remove_virtual_member");
            sqlx::query(
                r#"DELETE FROM virtual_repo_members
                   WHERE virtual_repo_id = $1 AND member_repo_id = $2"#,
            )
            .bind(virtual_repo_id)
            .bind(member_repo_id)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "VirtualRepoMember", &member_repo_id.to_string()))?;
            Ok(())
        })
    }

    fn replace_virtual_members(
        &self,
        virtual_repo_id: Uuid,
        ordered_member_ids: &[Uuid],
    ) -> BoxFuture<'_, DomainResult<()>> {
        // Own the ids so the returned future is `'static` (the borrowed slice
        // would otherwise have to outlive the call).
        let members: Vec<Uuid> = ordered_member_ids.to_vec();
        Box::pin(async move {
            tracing::debug!(
                entity = "Repository",
                %virtual_repo_id,
                member_count = members.len(),
                "replace_virtual_members (atomic)"
            );
            // One transaction: the DELETE + ordered re-INSERT commit together,
            // so a concurrent reader (another replica on the shared DB) sees
            // either the old set or the new set — never a partial set with the
            // owner edge transiently removed (ADR 0031 rule 2b).
            let mut tx = self.pool.begin().await.map_err(|e| {
                map_sqlx_error(&e, "VirtualRepoMember", &virtual_repo_id.to_string())
            })?;
            sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
                .bind(virtual_repo_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "VirtualRepoMember", &virtual_repo_id.to_string())
                })?;
            for (idx, member_repo_id) in members.iter().enumerate() {
                // `priority` = list index (0 = highest), so persisted order
                // tracks the declared `virtualMembers` order (ADR 0031 rule 3);
                // `get_virtual_members` reads `ORDER BY priority` ASC.
                sqlx::query(
                    r#"INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority)
                       VALUES ($1, $2, $3)"#,
                )
                .bind(virtual_repo_id)
                .bind(member_repo_id)
                .bind(idx as i32)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "VirtualRepoMember", &member_repo_id.to_string())
                })?;
            }
            tx.commit().await.map_err(|e| {
                map_sqlx_error(&e, "VirtualRepoMember", &virtual_repo_id.to_string())
            })?;
            Ok(())
        })
    }

    fn get_storage_usage(&self, repo_id: Uuid) -> BoxFuture<'_, DomainResult<u64>> {
        Box::pin(async move {
            tracing::debug!(entity = "Repository", %repo_id, "get_storage_usage");
            let usage: Option<i64> = sqlx::query_scalar(
                "SELECT COALESCE(SUM(size_bytes), 0) FROM artifacts WHERE repository_id = $1",
            )
            .bind(repo_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Repository", &repo_id.to_string()))?;
            let usage = usage.unwrap_or(0);

            Ok(usage as u64)
        })
    }

    fn save_managed(
        &self,
        repository: &Repository,
        digest: &[u8; 32],
    ) -> BoxFuture<'_, DomainResult<()>> {
        // Owned copies for the async block; identical INSERT-or-UPDATE
        // shape as `save()` plus the two managed columns hardcoded
        // to 'gitops' + the supplied digest. Keeping it as a separate
        // statement (rather than parameterising `save()`) makes the
        // gitops vs CRUD intent visible at the call site and prevents
        // an accidental managed-write from a code path that currently
        // builds `Repository { managed_by: GitOps, ... }` for some
        // unrelated reason.
        let repo = repository.clone();
        let digest = digest.to_vec();
        Box::pin(async move {
            tracing::info!(
                entity = "Repository",
                key = %repo.key,
                "save_managed (gitops apply)"
            );
            let format_str = repo.format.to_string();
            let repo_type_str = repo.repo_type.to_string();
            let replication_str = repo.replication_priority.to_string();

            let (promotion_target_id, promotion_policy_id) = match &repo.promotion {
                Some(p) => (Some(p.target_id), p.policy_id),
                None => (None, None),
            };

            let index_mode_str = repo.index_mode.to_string();
            // Same prefetch-column encoding as `save()`.
            let prefetch_triggers_db: Option<Vec<String>> =
                if repo.prefetch_policy.triggers.is_empty() {
                    None
                } else {
                    Some(
                        repo.prefetch_policy
                            .triggers
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                    )
                };
            let prefetch_depth_db: i32 = repo.prefetch_policy.depth as i32;
            let prefetch_transitive_depth_db: i32 = repo.prefetch_policy.transitive_depth as i32;
            let prefetch_max_age_db: Option<i32> =
                repo.prefetch_policy.max_age_days.map(|v| v as i32);
            // See `save()` for the wrap discipline; same encoding here.
            let prefetch_max_descendants_db: i32 = repo.prefetch_policy.max_descendants as i32;
            sqlx::query(
                r#"
                INSERT INTO repositories (
                    id, key, name, description,
                    format, repo_type,
                    storage_backend, storage_path, upstream_url,
                    index_upstream_url,
                    is_public, download_audit_enabled, index_mode,
                    prefetch_enabled, prefetch_triggers, prefetch_depth,
                    prefetch_transitive_depth, prefetch_max_age_days,
                    prefetch_max_descendants,
                    quota_bytes,
                    replication_priority,
                    promotion_target_id, promotion_policy_id,
                    created_at, updated_at,
                    managed_by, managed_by_digest
                )
                VALUES (
                    $1, $2, $3, $4,
                    $5::repository_format, $6::repository_type,
                    $7, $8, $9,
                    $10,
                    $11, $12, $13,
                    $14, $15, $16,
                    $17, $18,
                    $19,
                    $20,
                    $21::replication_priority,
                    $22, $23,
                    $24, $25,
                    'gitops', $26
                )
                ON CONFLICT (id) DO UPDATE SET
                    key = EXCLUDED.key,
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    format = EXCLUDED.format,
                    repo_type = EXCLUDED.repo_type,
                    storage_backend = EXCLUDED.storage_backend,
                    storage_path = EXCLUDED.storage_path,
                    upstream_url = EXCLUDED.upstream_url,
                    index_upstream_url = EXCLUDED.index_upstream_url,
                    is_public = EXCLUDED.is_public,
                    download_audit_enabled = EXCLUDED.download_audit_enabled,
                    index_mode = EXCLUDED.index_mode,
                    prefetch_enabled = EXCLUDED.prefetch_enabled,
                    prefetch_triggers = EXCLUDED.prefetch_triggers,
                    prefetch_depth = EXCLUDED.prefetch_depth,
                    prefetch_transitive_depth = EXCLUDED.prefetch_transitive_depth,
                    prefetch_max_age_days = EXCLUDED.prefetch_max_age_days,
                    prefetch_max_descendants = EXCLUDED.prefetch_max_descendants,
                    quota_bytes = EXCLUDED.quota_bytes,
                    replication_priority = EXCLUDED.replication_priority,
                    promotion_target_id = EXCLUDED.promotion_target_id,
                    promotion_policy_id = EXCLUDED.promotion_policy_id,
                    updated_at = EXCLUDED.updated_at,
                    managed_by = 'gitops',
                    managed_by_digest = EXCLUDED.managed_by_digest
                "#,
            )
            .bind(repo.id)
            .bind(&repo.key)
            .bind(&repo.name)
            .bind(&repo.description)
            .bind(&format_str)
            .bind(&repo_type_str)
            .bind(&repo.storage_backend)
            .bind(&repo.storage_path)
            .bind(&repo.upstream_url)
            .bind(&repo.index_upstream_url)
            .bind(repo.is_public)
            .bind(repo.download_audit_enabled)
            .bind(&index_mode_str)
            .bind(repo.prefetch_policy.enabled)
            .bind(&prefetch_triggers_db)
            .bind(prefetch_depth_db)
            .bind(prefetch_transitive_depth_db)
            .bind(prefetch_max_age_db)
            .bind(prefetch_max_descendants_db)
            .bind(repo.quota_bytes)
            .bind(&replication_str)
            .bind(promotion_target_id)
            .bind(promotion_policy_id)
            .bind(repo.created_at)
            .bind(repo.updated_at)
            .bind(&digest)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Repository", &repo.key))?;

            Ok(())
        })
    }

    fn delete_managed(&self, id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::info!(entity = "Repository", %id, "delete_managed (gitops apply)");
            // Defence in depth: refuse to delete non-gitops rows even
            // though the diff layer never schedules such a delete. The
            // WHERE clause does the filtering; rows_affected == 0 maps
            // to NotFound (the row didn't exist or wasn't managed).
            let result =
                sqlx::query("DELETE FROM repositories WHERE id = $1 AND managed_by = 'gitops'")
                    .bind(id)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| map_sqlx_error(&e, "Repository", &id.to_string()))?;

            if result.rows_affected() == 0 {
                return Err(DomainError::NotFound {
                    entity: "Repository",
                    id: id.to_string(),
                });
            }
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{
        IndexMode, PrefetchPolicy, PrefetchTrigger, ReplicationPriority, Repository,
        RepositoryFormat, RepositoryType,
    };
    use serial_test::serial;
    use std::env;

    // -- Compile-time port proof -------------------------------------------

    #[test]
    fn pg_repository_repository_implements_port() {
        fn _assert_port<T: RepositoryRepository>() {}
        _assert_port::<PgRepositoryRepository>();
    }

    // -- DB-backed integration round-trip ----------------------------------
    //
    // The `index_mode` column round-trips end-to-end through
    // `save_managed → find_by_key` for both variants. `#[serial(hort_pg_db)]`
    // per ADR 0019 — every `maybe_pool()` caller serializes on the
    // crate-wide key to avoid the parallel-DB identity-shift flake the
    // project memory pins (`project_v2_db_tests_need_fresh_db`).

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    fn sample_repository(key: &str, index_mode: IndexMode) -> Repository {
        let now = Utc::now();
        Repository {
            id: Uuid::new_v4(),
            key: key.into(),
            name: key.into(),
            description: None,
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Proxy,
            storage_backend: "filesystem".into(),
            storage_path: format!("/tmp/{key}"),
            upstream_url: Some("https://registry.npmjs.org".into()),
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode,
            prefetch_policy: PrefetchPolicy::default(),
            created_at: now,
            updated_at: now,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0u8; 32]),
        }
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_round_trips_index_mode_include_pending() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = PgRepositoryRepository::new(pool.clone());
        let key = format!("it-idx-mode-ip-{}", Uuid::new_v4().simple());
        let repo = sample_repository(&key, IndexMode::IncludePending);

        adapter
            .save_managed(&repo, &[0x47u8; 32])
            .await
            .expect("save_managed");

        let loaded = adapter.find_by_key(&key).await.expect("find_by_key");
        assert_eq!(loaded.index_mode, IndexMode::IncludePending);
        assert_eq!(loaded.key, key);
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_round_trips_index_mode_released_only_default() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = PgRepositoryRepository::new(pool.clone());
        let key = format!("it-idx-mode-ro-{}", Uuid::new_v4().simple());
        let repo = sample_repository(&key, IndexMode::ReleasedOnly);

        adapter
            .save_managed(&repo, &[0x47u8; 32])
            .await
            .expect("save_managed");

        let loaded = adapter.find_by_key(&key).await.expect("find_by_key");
        assert_eq!(loaded.index_mode, IndexMode::ReleasedOnly);
    }

    /// The `repositories_index_mode_check` CHECK constraint
    /// (`002_repositories.sql`) rejects an out-of-domain literal at
    /// write time. The save path can't emit one (the enum's `Display`
    /// only produces the two valid strings), so we exercise the CHECK
    /// by writing the raw bad string with `sqlx::query` to confirm the
    /// migration locks it down.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn index_mode_check_constraint_rejects_unknown_literal() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        // Seed a repository with a deliberately bad `index_mode` —
        // expect a CheckViolation from Postgres (SQLSTATE 23514).
        let id = Uuid::new_v4();
        let key = format!("it-idx-mode-check-{}", id.simple());
        let result = sqlx::query(
            r#"INSERT INTO repositories (
                   id, key, name, format, repo_type, storage_backend, storage_path,
                   replication_priority, index_mode
               ) VALUES (
                   $1, $2, $3,
                   'npm'::repository_format,
                   'hosted'::repository_type,
                   'filesystem', $4,
                   'local_only'::replication_priority,
                   'permissive'
               )"#,
        )
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .execute(&pool)
        .await;

        let err = result.expect_err("CHECK constraint must reject 'permissive'");
        let msg = err.to_string();
        // SQLSTATE 23514 = check_violation. The constraint name surfaces
        // in the message — pin it so a rename without a migration breaks
        // the test.
        assert!(
            msg.contains("repositories_index_mode_check") || msg.contains("23514"),
            "expected index_mode CHECK violation, got: {msg}"
        );
    }

    // -- virtual-member atomic replace (ADR 0031 / S-2) ------------------------

    /// `replace_virtual_members` swaps the entire member set to exactly the
    /// declared ids, in declared priority order, in one transaction. This pins
    /// the behavioural contract (final state + ordering); the *atomicity* it
    /// adds (a concurrent reader never sees a partial set) is structural — the
    /// single `begin()`/`commit()` — and is not reproduced here as a race.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn replace_virtual_members_swaps_to_declared_set_and_order() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = PgRepositoryRepository::new(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let vroot = sample_repository(&format!("it-vroot-{suffix}"), IndexMode::ReleasedOnly);
        let a = sample_repository(&format!("it-vm-a-{suffix}"), IndexMode::ReleasedOnly);
        let b = sample_repository(&format!("it-vm-b-{suffix}"), IndexMode::ReleasedOnly);
        let c = sample_repository(&format!("it-vm-c-{suffix}"), IndexMode::ReleasedOnly);
        for r in [&vroot, &a, &b, &c] {
            adapter
                .save_managed(r, &[0u8; 32])
                .await
                .expect("save_managed");
        }
        // Seed an initial member set [a, b, c] via the per-edge add path.
        for m in [&a, &b, &c] {
            adapter
                .add_virtual_member(vroot.id, m.id)
                .await
                .expect("add_virtual_member");
        }

        // Atomic replace → [c, a]: drops b and re-pins the priority order.
        adapter
            .replace_virtual_members(vroot.id, &[c.id, a.id])
            .await
            .expect("replace_virtual_members");

        let ordered: Vec<Uuid> = adapter
            .get_virtual_members(vroot.id)
            .await
            .expect("get_virtual_members")
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(
            ordered,
            vec![c.id, a.id],
            "replace swaps to exactly the declared set, in declared priority order"
        );

        // Replacing with an empty list clears the set entirely.
        adapter
            .replace_virtual_members(vroot.id, &[])
            .await
            .expect("replace_virtual_members empty");
        let empty: Vec<Uuid> = adapter
            .get_virtual_members(vroot.id)
            .await
            .expect("get_virtual_members")
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert!(empty.is_empty(), "empty replace clears all edges");
    }

    // -- prefetch policy round-trip --------------------------------------------

    /// A non-default `PrefetchPolicy` (all five fields set to non-
    /// canonical values, every Phase-1 trigger selected) round-trips
    /// through `save_managed → find_by_key` unchanged. Mirrors the
    /// `index_mode` round-trip locks above.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_round_trips_non_default_prefetch_policy() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = PgRepositoryRepository::new(pool.clone());
        let key = format!("it-prefetch-rt-{}", Uuid::new_v4().simple());
        let mut repo = sample_repository(&key, IndexMode::ReleasedOnly);
        repo.prefetch_policy = PrefetchPolicy {
            enabled: true,
            triggers: vec![
                PrefetchTrigger::TransitiveDeps,
                PrefetchTrigger::Scheduled,
                PrefetchTrigger::OnDistTagMove,
            ],
            depth: 12,
            transitive_depth: 7,
            max_age_days: Some(180),
            // Non-default sentinel so the round-trip exercises the new
            // column end-to-end.
            max_descendants: 750,
        };

        adapter
            .save_managed(&repo, &[0x47u8; 32])
            .await
            .expect("save_managed");

        let loaded = adapter.find_by_key(&key).await.expect("find_by_key");
        assert_eq!(loaded.prefetch_policy, repo.prefetch_policy);
    }

    /// The default policy (disabled, empty triggers, default depths)
    /// round-trips — exercises the NULL-`prefetch_triggers` branch of
    /// the bind path (the canonical "no triggers" representation).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_round_trips_default_prefetch_policy_no_triggers() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = PgRepositoryRepository::new(pool.clone());
        let key = format!("it-prefetch-default-{}", Uuid::new_v4().simple());
        // sample_repository already sets `prefetch_policy: PrefetchPolicy::default()`.
        let repo = sample_repository(&key, IndexMode::ReleasedOnly);

        adapter
            .save_managed(&repo, &[0x47u8; 32])
            .await
            .expect("save_managed");

        let loaded = adapter.find_by_key(&key).await.expect("find_by_key");
        assert_eq!(loaded.prefetch_policy, PrefetchPolicy::default());
        // Belt-and-braces — the SQL NULL on `prefetch_triggers`
        // surfaces as an empty `Vec` on the way back, NOT as a synthetic
        // `vec![]` produced by the mapper from a non-NULL empty `'{}'`.
        // Both representations collapse domain-side, but the bind path
        // is asserted to chose NULL when the trigger list is empty.
        let raw_triggers: Option<Vec<String>> = sqlx::query_scalar::<_, Option<Vec<String>>>(
            "SELECT prefetch_triggers FROM repositories WHERE key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("scalar prefetch_triggers");
        assert!(
            raw_triggers.is_none(),
            "empty triggers must persist as SQL NULL (the canonical \"no triggers\" representation), got {raw_triggers:?}"
        );
    }

    /// The `repositories_prefetch_triggers_check` CHECK constraint
    /// rejects an out-of-domain literal on the `prefetch_triggers`
    /// element value at write time. The save path cannot emit one
    /// (the enum's `Display` only produces the four valid strings),
    /// so we exercise the CHECK by writing the raw bad array with
    /// `sqlx::query` — confirms the migration locks it down.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn prefetch_triggers_check_constraint_rejects_unknown_literal() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let id = Uuid::new_v4();
        let key = format!("it-prefetch-check-{}", id.simple());
        let result = sqlx::query(
            r#"INSERT INTO repositories (
                   id, key, name, format, repo_type, storage_backend, storage_path,
                   replication_priority, index_mode, prefetch_triggers
               ) VALUES (
                   $1, $2, $3,
                   'npm'::repository_format,
                   'hosted'::repository_type,
                   'filesystem', $4,
                   'local_only'::replication_priority,
                   'released_only',
                   ARRAY['scheduled', 'eager']::text[]
               )"#,
        )
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .execute(&pool)
        .await;

        let err = result.expect_err("CHECK constraint must reject 'eager' element");
        let msg = err.to_string();
        assert!(
            msg.contains("repositories_prefetch_triggers_check") || msg.contains("23514"),
            "expected prefetch_triggers CHECK violation, got: {msg}"
        );
    }
}
