//! Postgres implementation of `CurationRuleRepository`.
//!
//! Read paths:
//! - `find_by_name` / `find_by_id` — diagnostic lookups; both use the
//!   shared `SELECT_COLS` projection and the same row mapper.
//! - `list_for_repo` — curation-evaluator hot path; joins the
//!   junction first so we only read rules actually attached to the repo.
//! - `list_managed_by_gitops` — bound by the partial index
//!   `idx_curation_rules_managed_by` (`006_curation.sql`).
//!
//! Write paths target `managed_by = 'gitops'` rows exclusively. The
//! defensive `WHERE managed_by = 'gitops'` on `delete_managed` mirrors
//! the `group_mapping_repo.rs` pattern: the diff layer never schedules
//! a delete on a `managed_by = 'local'` row, but enforcing it here
//! prevents collateral damage from out-of-band SQL.
//!
//! `set_curation_rules_for_repository` runs delete-then-insert in a
//! single transaction — partial failures leave the previous attachment
//! set intact, idempotent re-applies converge on the same final state.

use std::str::FromStr;

use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;

use crate::BoxFuture;

pub struct PgCurationRuleRepository {
    pool: PgPool,
}

impl PgCurationRuleRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const SELECT_COLS: &str =
    "id, name, format, package_pattern, action, reason, managed_by, managed_by_digest";

#[derive(Debug, FromRow)]
struct CurationRuleRow {
    id: Uuid,
    name: String,
    format: Option<String>,
    package_pattern: String,
    action: String,
    reason: String,
    managed_by: String,
    managed_by_digest: Option<Vec<u8>>,
}

/// Map a row to the domain entity. Pure — no I/O.
fn row_to_rule(row: CurationRuleRow) -> DomainResult<CurationRule> {
    let action = CurationRuleAction::from_str(&row.action).map_err(|_| {
        tracing::warn!(
            action = %row.action,
            id = %row.id,
            "unknown action in curation_rules row"
        );
        DomainError::Invariant(format!(
            "corrupt action value in curation_rules row: {}",
            row.action
        ))
    })?;

    // RepositoryFormat::FromStr maps unknowns to `Other(_)` infallibly;
    // we accept that for parity with the row mapper used by repositories.
    let format = row.format.map(|s| s.parse::<RepositoryFormat>().unwrap());

    let managed_by = row.managed_by.parse().unwrap_or(ManagedBy::Local);
    let managed_by_digest = row
        .managed_by_digest
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok());

    Ok(CurationRule {
        id: row.id,
        name: row.name,
        format,
        package_pattern: row.package_pattern,
        action,
        reason: row.reason,
        managed_by,
        managed_by_digest,
    })
}

impl CurationRuleRepository for PgCurationRuleRepository {
    fn find_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<Option<CurationRule>>> {
        let name = name.to_string();
        Box::pin(async move {
            tracing::debug!(entity = "curation_rule", name = %name, "find_by_name");
            let sql = format!("SELECT {SELECT_COLS} FROM curation_rules WHERE name = $1 LIMIT 1");
            let row: Option<CurationRuleRow> = sqlx::query_as(&sql)
                .bind(&name)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    tracing::warn!(name = %name, error = %e, "curation_rules find_by_name");
                    DomainError::Invariant(format!("curation_rules find_by_name: {e}"))
                })?;
            row.map(row_to_rule).transpose()
        })
    }

    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Option<CurationRule>>> {
        Box::pin(async move {
            tracing::debug!(entity = "curation_rule", %id, "find_by_id");
            let sql = format!("SELECT {SELECT_COLS} FROM curation_rules WHERE id = $1 LIMIT 1");
            let row: Option<CurationRuleRow> = sqlx::query_as(&sql)
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    tracing::warn!(%id, error = %e, "curation_rules find_by_id");
                    DomainError::Invariant(format!("curation_rules find_by_id: {e}"))
                })?;
            row.map(row_to_rule).transpose()
        })
    }

    fn list_for_repo(&self, repository_id: Uuid) -> BoxFuture<'_, DomainResult<Vec<CurationRule>>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "curation_rule",
                %repository_id,
                "list_for_repo"
            );
            let rows: Vec<CurationRuleRow> = sqlx::query_as(&format!(
                r#"SELECT {SELECT_COLS}
                   FROM curation_rules cr
                   JOIN repository_curation_rules rcr ON rcr.curation_rule_id = cr.id
                   WHERE rcr.repository_id = $1
                   ORDER BY cr.name"#
            ))
            .bind(repository_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(%repository_id, error = %e, "curation_rules list_for_repo");
                DomainError::Invariant(format!("curation_rules list_for_repo: {e}"))
            })?;
            rows.into_iter().map(row_to_rule).collect()
        })
    }

    fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<CurationRule>>> {
        Box::pin(async move {
            tracing::debug!(entity = "curation_rule", "list_managed_by_gitops");
            let rows: Vec<CurationRuleRow> = sqlx::query_as(&format!(
                r#"SELECT {SELECT_COLS}
                   FROM curation_rules
                   WHERE managed_by = 'gitops'
                   ORDER BY name"#
            ))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "curation_rules list_managed_by_gitops");
                DomainError::Invariant(format!("curation_rules list_managed_by_gitops: {e}"))
            })?;
            rows.into_iter().map(row_to_rule).collect()
        })
    }

    fn save_managed(&self, rule: &CurationRule) -> BoxFuture<'_, DomainResult<()>> {
        let id = rule.id;
        let name = rule.name.clone();
        let format = rule.format.as_ref().map(ToString::to_string);
        let package_pattern = rule.package_pattern.clone();
        let action = rule.action.to_string();
        let reason = rule.reason.clone();
        // The port contract ignores the rule's own managed_by field —
        // the adapter writes 'gitops' unconditionally to make the
        // intent explicit at the call site. The digest is required;
        // a managed-write without a digest violates the schema CHECK,
        // so we surface that as a domain Invariant rather than letting
        // sqlx surface a CHECK error string.
        let digest = rule.managed_by_digest.ok_or_else(|| {
            DomainError::Invariant(format!(
                "save_managed requires managed_by_digest on rule {name}"
            ))
        });
        Box::pin(async move {
            let digest = digest?.to_vec();
            tracing::info!(
                entity = "curation_rule",
                name = %name,
                "save_managed (gitops apply)"
            );
            sqlx::query(
                r#"INSERT INTO curation_rules
                       (id, name, format, package_pattern, action, reason,
                        managed_by, managed_by_digest)
                   VALUES ($1, $2, $3, $4, $5, $6, 'gitops', $7)
                   ON CONFLICT (name) DO UPDATE SET
                       format            = EXCLUDED.format,
                       package_pattern   = EXCLUDED.package_pattern,
                       action            = EXCLUDED.action,
                       reason            = EXCLUDED.reason,
                       managed_by        = 'gitops',
                       managed_by_digest = EXCLUDED.managed_by_digest,
                       updated_at        = NOW()"#,
            )
            .bind(id)
            .bind(&name)
            .bind(&format)
            .bind(&package_pattern)
            .bind(&action)
            .bind(&reason)
            .bind(&digest)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(name = %name, error = %e, "curation_rules save_managed");
                DomainError::Invariant(format!("curation_rules save_managed: {e}"))
            })?;
            Ok(())
        })
    }

    fn delete_managed(&self, name: &str) -> BoxFuture<'_, DomainResult<()>> {
        let name = name.to_string();
        Box::pin(async move {
            tracing::info!(
                entity = "curation_rule",
                name = %name,
                "delete_managed (gitops apply)"
            );
            // Defensive WHERE clause: refuses non-gitops rows. Returns
            // NotFound when the row doesn't exist OR isn't managed.
            let result = sqlx::query(
                r#"DELETE FROM curation_rules
                   WHERE name = $1 AND managed_by = 'gitops'"#,
            )
            .bind(&name)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(name = %name, error = %e, "curation_rules delete_managed");
                DomainError::Invariant(format!("curation_rules delete_managed: {e}"))
            })?;
            if result.rows_affected() == 0 {
                return Err(DomainError::NotFound {
                    entity: "CurationRule",
                    id: name,
                });
            }
            Ok(())
        })
    }

    fn list_repos_for_rule(&self, rule_id: Uuid) -> BoxFuture<'_, DomainResult<Vec<Uuid>>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "curation_rule",
                %rule_id,
                "list_repos_for_rule"
            );
            // Reverse-index lookup for the apply-pipeline retroactive pass.
            // Returns every repository attached to the rule via the
            // `repository_curation_rules` junction.
            let ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT repository_id FROM repository_curation_rules \
                 WHERE curation_rule_id = $1",
            )
            .bind(rule_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(%rule_id, error = %e, "curation_rules list_repos_for_rule");
                DomainError::Invariant(format!("curation_rules list_repos_for_rule: {e}"))
            })?;
            Ok(ids)
        })
    }

    fn set_curation_rules_for_repository(
        &self,
        repository_id: Uuid,
        rule_ids: &[Uuid],
    ) -> BoxFuture<'_, DomainResult<()>> {
        let rule_ids = rule_ids.to_vec();
        Box::pin(async move {
            tracing::info!(
                entity = "curation_rule",
                %repository_id,
                rule_count = rule_ids.len(),
                "set_curation_rules_for_repository (gitops apply)"
            );
            let mut tx = self.pool.begin().await.map_err(|e| {
                tracing::warn!(%repository_id, error = %e, "begin tx for set_curation_rules_for_repository");
                DomainError::Invariant(format!(
                    "begin tx for set_curation_rules_for_repository: {e}"
                ))
            })?;

            sqlx::query("DELETE FROM repository_curation_rules WHERE repository_id = $1")
                .bind(repository_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::warn!(%repository_id, error = %e, "delete junction edges");
                    DomainError::Invariant(format!("delete junction edges: {e}"))
                })?;

            // Replace the per-edge INSERT loop with a single statement that
            // unnests the rule_ids array. The empty-slice case skips
            // the INSERT entirely — the DELETE alone is correct, and
            // emitting `INSERT … FROM unnest(ARRAY[]::uuid[])` would
            // be a noisy no-op. The DELETE + INSERT remain in the same
            // transaction so a failure rolls back to the previous
            // attachment set unchanged.
            if !rule_ids.is_empty() {
                sqlx::query(
                    "INSERT INTO repository_curation_rules (repository_id, curation_rule_id) \
                     SELECT $1, rule_id FROM unnest($2::uuid[]) AS x(rule_id)",
                )
                .bind(repository_id)
                .bind(&rule_ids)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::warn!(%repository_id, error = %e, "insert junction edges");
                    DomainError::Invariant(format!("insert junction edges: {e}"))
                })?;
            }

            tx.commit().await.map_err(|e| {
                tracing::warn!(%repository_id, error = %e, "commit set_curation_rules_for_repository");
                DomainError::Invariant(format!(
                    "commit set_curation_rules_for_repository: {e}"
                ))
            })?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Tests — pure mapper helpers + DB-backed integration covered when
// `DATABASE_URL` is set (Tier-2 CI). Mirrors `policy_projection_repo.rs`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    // -- Pure mapper helpers -------------------------------------------------

    fn sample_row() -> CurationRuleRow {
        CurationRuleRow {
            id: Uuid::nil(),
            name: "block-cve-2024-3094".into(),
            format: Some("npm".into()),
            package_pattern: "xz-utils*".into(),
            action: "block".into(),
            reason: "CVE-2024-3094".into(),
            managed_by: "gitops".into(),
            managed_by_digest: Some(vec![0xab; 32]),
        }
    }

    #[test]
    fn row_to_rule_carries_all_fields() {
        let r = row_to_rule(sample_row()).unwrap();
        assert_eq!(r.name, "block-cve-2024-3094");
        assert_eq!(r.format, Some(RepositoryFormat::Npm));
        assert_eq!(r.action, CurationRuleAction::Block);
        assert_eq!(r.reason, "CVE-2024-3094");
        assert_eq!(r.managed_by, ManagedBy::GitOps);
        assert_eq!(r.managed_by_digest, Some([0xab; 32]));
    }

    #[test]
    fn row_to_rule_format_none_means_any() {
        let row = CurationRuleRow {
            format: None,
            ..sample_row()
        };
        let r = row_to_rule(row).unwrap();
        assert!(r.format.is_none());
    }

    #[test]
    fn row_to_rule_unknown_format_becomes_other() {
        let row = CurationRuleRow {
            format: Some("flatpak".into()),
            ..sample_row()
        };
        let r = row_to_rule(row).unwrap();
        assert_eq!(r.format, Some(RepositoryFormat::Other("flatpak".into())));
    }

    #[test]
    fn row_to_rule_unknown_action_is_invariant() {
        let row = CurationRuleRow {
            action: "deny".into(),
            ..sample_row()
        };
        let err = row_to_rule(row).unwrap_err();
        match err {
            DomainError::Invariant(msg) => assert!(msg.contains("deny")),
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    #[test]
    fn row_to_rule_local_with_no_digest_round_trips() {
        let row = CurationRuleRow {
            managed_by: "local".into(),
            managed_by_digest: None,
            ..sample_row()
        };
        let r = row_to_rule(row).unwrap();
        assert_eq!(r.managed_by, ManagedBy::Local);
        assert!(r.managed_by_digest.is_none());
    }

    #[test]
    fn row_to_rule_unknown_managed_by_defaults_to_local() {
        let row = CurationRuleRow {
            managed_by: "external".into(),
            managed_by_digest: None,
            ..sample_row()
        };
        let r = row_to_rule(row).unwrap();
        assert_eq!(r.managed_by, ManagedBy::Local);
    }

    #[test]
    fn row_to_rule_wrong_digest_length_drops_digest() {
        let row = CurationRuleRow {
            managed_by: "gitops".into(),
            managed_by_digest: Some(vec![0; 16]),
            ..sample_row()
        };
        let r = row_to_rule(row).unwrap();
        assert!(r.managed_by_digest.is_none());
    }

    // -- Construction smoke --------------------------------------------------

    #[tokio::test]
    async fn pg_curation_rule_repo_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL");
        let _ = PgCurationRuleRepository::new(pool);
    }

    // -- DB-backed integration tests (skipped when DATABASE_URL is unset) ----

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    /// Helper: insert a managed rule directly (bypasses save_managed
    /// quirks). Returns the inserted `id`.
    async fn insert_managed(pool: &PgPool, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO curation_rules
                   (id, name, format, package_pattern, action, reason,
                    managed_by, managed_by_digest)
               VALUES ($1, $2, NULL, 'pkg-*', 'block', 'r', 'gitops', $3)"#,
        )
        .bind(id)
        .bind(name)
        .bind(vec![0xab_u8; 32])
        .execute(pool)
        .await
        .expect("insert managed");
        id
    }

    /// Helper: insert a hosted repository so the junction-table FK
    /// resolves. Returns the inserted `id`.
    async fn insert_repo(pool: &PgPool, key: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO repositories
                   (id, key, name, description, format, repo_type,
                    storage_backend, storage_path, upstream_url,
                    is_public, quota_bytes, replication_priority,
                    created_at, updated_at)
               VALUES ($1, $2, $2, NULL, 'npm'::repository_format,
                       'hosted'::repository_type,
                       'filesystem', $3, NULL,
                       true, NULL,
                       'on_demand'::replication_priority,
                       NOW(), NOW())"#,
        )
        .bind(id)
        .bind(key)
        .bind(format!("/data/{key}"))
        .execute(pool)
        .await
        .expect("insert repo");
        id
    }

    fn sample_managed_rule(id: Uuid, name: &str) -> CurationRule {
        CurationRule {
            id,
            name: name.into(),
            format: Some(RepositoryFormat::Pypi),
            package_pattern: "left-pad*".into(),
            action: CurationRuleAction::Warn,
            reason: "supply-chain risk".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xcd; 32]),
        }
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_then_find_by_name() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgCurationRuleRepository::new(pool);
        let id = Uuid::new_v4();
        let name = format!("rule-{}", id.simple());
        let rule = sample_managed_rule(id, &name);

        repo.save_managed(&rule).await.expect("save_managed");
        let fetched = repo
            .find_by_name(&name)
            .await
            .expect("find_by_name")
            .expect("row exists");
        assert_eq!(fetched.id, rule.id);
        assert_eq!(fetched.action, CurationRuleAction::Warn);
        assert_eq!(fetched.format, Some(RepositoryFormat::Pypi));
        assert_eq!(fetched.managed_by, ManagedBy::GitOps);
        assert_eq!(fetched.managed_by_digest, Some([0xcd; 32]));
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_upserts_existing() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgCurationRuleRepository::new(pool);
        let id = Uuid::new_v4();
        let name = format!("upd-{}", id.simple());
        let mut rule = sample_managed_rule(id, &name);

        repo.save_managed(&rule).await.expect("first save_managed");
        rule.action = CurationRuleAction::Block;
        rule.reason = "revoked".into();
        rule.managed_by_digest = Some([0xee; 32]);
        repo.save_managed(&rule).await.expect("second save_managed");

        let fetched = repo
            .find_by_name(&name)
            .await
            .expect("find_by_name")
            .expect("row exists");
        assert_eq!(fetched.action, CurationRuleAction::Block);
        assert_eq!(fetched.reason, "revoked");
        assert_eq!(fetched.managed_by_digest, Some([0xee; 32]));
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_managed_by_gitops_returns_only_gitops_rows() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let name = format!("listmgd-{}", Uuid::new_v4().simple());
        insert_managed(&pool, &name).await;
        let repo = PgCurationRuleRepository::new(pool);
        let rules = repo
            .list_managed_by_gitops()
            .await
            .expect("list_managed_by_gitops");
        assert!(rules.iter().any(|r| r.name == name));
        assert!(rules.iter().all(|r| r.managed_by == ManagedBy::GitOps));
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn delete_managed_refuses_local_rows() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let id = Uuid::new_v4();
        let name = format!("local-{}", id.simple());
        sqlx::query(
            r#"INSERT INTO curation_rules
                   (id, name, format, package_pattern, action, reason,
                    managed_by, managed_by_digest)
               VALUES ($1, $2, NULL, 'pkg-*', 'allow', 'r', 'local', NULL)"#,
        )
        .bind(id)
        .bind(&name)
        .execute(&pool)
        .await
        .expect("insert local");

        let repo = PgCurationRuleRepository::new(pool);
        let err = repo.delete_managed(&name).await.unwrap_err();
        assert!(matches!(err, DomainError::NotFound { .. }));
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn delete_managed_removes_gitops_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let name = format!("delmgd-{}", Uuid::new_v4().simple());
        insert_managed(&pool, &name).await;
        let repo = PgCurationRuleRepository::new(pool);
        repo.delete_managed(&name).await.expect("delete_managed");
        let fetched = repo.find_by_name(&name).await.expect("find_by_name");
        assert!(fetched.is_none());
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn set_curation_rules_for_repository_replaces_set() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_key = format!("repo-{}", Uuid::new_v4().simple());
        let repo_id = insert_repo(&pool, &repo_key).await;
        let rule1 = insert_managed(&pool, &format!("r1-{}", Uuid::new_v4().simple())).await;
        let rule2 = insert_managed(&pool, &format!("r2-{}", Uuid::new_v4().simple())).await;
        let rule3 = insert_managed(&pool, &format!("r3-{}", Uuid::new_v4().simple())).await;

        let adapter = PgCurationRuleRepository::new(pool.clone());

        // First set: {rule1, rule2}.
        adapter
            .set_curation_rules_for_repository(repo_id, &[rule1, rule2])
            .await
            .expect("first set");
        let attached: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT curation_rule_id FROM repository_curation_rules WHERE repository_id = $1",
        )
        .bind(repo_id)
        .fetch_all(&pool)
        .await
        .expect("read junction");
        let attached_ids: std::collections::HashSet<Uuid> =
            attached.into_iter().map(|(id,)| id).collect();
        assert_eq!(attached_ids.len(), 2);
        assert!(attached_ids.contains(&rule1));
        assert!(attached_ids.contains(&rule2));

        // Second set: {rule3} — replaces the previous set wholesale.
        adapter
            .set_curation_rules_for_repository(repo_id, &[rule3])
            .await
            .expect("second set");
        let attached: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT curation_rule_id FROM repository_curation_rules WHERE repository_id = $1",
        )
        .bind(repo_id)
        .fetch_all(&pool)
        .await
        .expect("read junction");
        let attached_ids: std::collections::HashSet<Uuid> =
            attached.into_iter().map(|(id,)| id).collect();
        assert_eq!(attached_ids, [rule3].into_iter().collect());
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn set_curation_rules_for_repository_idempotent_empty() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_key = format!("empty-{}", Uuid::new_v4().simple());
        let repo_id = insert_repo(&pool, &repo_key).await;
        let adapter = PgCurationRuleRepository::new(pool.clone());

        adapter
            .set_curation_rules_for_repository(repo_id, &[])
            .await
            .expect("first empty set");
        adapter
            .set_curation_rules_for_repository(repo_id, &[])
            .await
            .expect("second empty set");

        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM repository_curation_rules WHERE repository_id = $1",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(count.0, 0);
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_for_repo_returns_attached_rules_only() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_key = format!("listrepo-{}", Uuid::new_v4().simple());
        let repo_id = insert_repo(&pool, &repo_key).await;
        let attached_name = format!("attached-{}", Uuid::new_v4().simple());
        let unrelated_name = format!("unrelated-{}", Uuid::new_v4().simple());
        let attached_id = insert_managed(&pool, &attached_name).await;
        let _unrelated_id = insert_managed(&pool, &unrelated_name).await;

        let adapter = PgCurationRuleRepository::new(pool);
        adapter
            .set_curation_rules_for_repository(repo_id, &[attached_id])
            .await
            .expect("attach");

        let rules = adapter.list_for_repo(repo_id).await.expect("list_for_repo");
        let names: Vec<String> = rules.iter().map(|r| r.name.clone()).collect();
        assert_eq!(names, vec![attached_name]);
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_id_returns_none_for_missing_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgCurationRuleRepository::new(pool);
        let result = repo
            .find_by_id(Uuid::new_v4())
            .await
            .expect("find_by_id call");
        assert!(result.is_none());
    }
}
