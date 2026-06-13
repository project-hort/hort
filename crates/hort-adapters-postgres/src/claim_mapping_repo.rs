//! Postgres implementation of [`ClaimMappingRepository`].
//!
//! Read paths back the boot caller's seed of `AuthenticateUseCase`
//! (`list_all`) and the apply diff (`list_managed_by_gitops`). The write
//! path is exclusively for the gitops apply pipeline — the API surface
//! for adding a mapping is a YAML edit + restart, never a direct SQL
//! write.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::ClaimMapping;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::claim_mapping_repository::ClaimMappingRepository;

use crate::{map_sqlx_error, BoxFuture};

pub struct PgClaimMappingRepository {
    pool: PgPool,
}

impl PgClaimMappingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const CLAIM_MAPPING_SELECT_COLS: &str =
    "id, idp_group, claim, managed_by, managed_by_digest, created_at";

/// Database row for the `claim_mappings` table.
#[derive(Debug, FromRow)]
pub(crate) struct ClaimMappingRow {
    pub id: Uuid,
    pub idp_group: String,
    pub claim: String,
    pub managed_by: String,
    pub managed_by_digest: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
}

/// Owned column projection of a managed [`ClaimMapping`], built before
/// the `save_managed` transaction opens so the future borrows nothing
/// from `items`. Named struct (not a 4-tuple) to keep the reconcile
/// INSERT loop readable and to satisfy `clippy::type_complexity` —
/// behaviour is identical to the prior tuple form.
struct PreparedClaimMapping {
    id: Uuid,
    idp_group: String,
    claim: String,
    digest: Vec<u8>,
}

/// Infallible mapping from `ClaimMappingRow` to the domain
/// [`ClaimMapping`]. An unknown `managed_by` literal coerces to `Local`
/// (the DB CHECK blocks it in practice); a wrong-length digest is
/// treated as "no digest known" — the diff layer surfaces it as an
/// `update` on the next apply rather than panicking the mapper.
pub(crate) fn row_to_claim_mapping(row: ClaimMappingRow) -> ClaimMapping {
    let managed_by = row.managed_by.parse().unwrap_or(ManagedBy::Local);
    let managed_by_digest = row
        .managed_by_digest
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok());
    ClaimMapping {
        id: row.id,
        idp_group: row.idp_group,
        claim: row.claim,
        managed_by,
        managed_by_digest,
    }
}

impl ClaimMappingRepository for PgClaimMappingRepository {
    fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<ClaimMapping>>> {
        Box::pin(async move {
            tracing::debug!(entity = "ClaimMapping", "list_all");
            let sql = format!(
                "SELECT {CLAIM_MAPPING_SELECT_COLS} FROM claim_mappings \
                 ORDER BY idp_group, claim"
            );
            let rows: Vec<ClaimMappingRow> = sqlx::query_as(&sql)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ClaimMapping", "list_all"))?;
            Ok(rows.into_iter().map(row_to_claim_mapping).collect())
        })
    }

    fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<ClaimMapping>>> {
        Box::pin(async move {
            tracing::debug!(entity = "ClaimMapping", "list_managed_by_gitops");
            let sql = format!(
                "SELECT {CLAIM_MAPPING_SELECT_COLS} FROM claim_mappings \
                 WHERE managed_by = 'gitops' ORDER BY idp_group, claim"
            );
            let rows: Vec<ClaimMappingRow> = sqlx::query_as(&sql)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ClaimMapping", "list_managed_by_gitops"))?;
            Ok(rows.into_iter().map(row_to_claim_mapping).collect())
        })
    }

    fn save_managed(&self, items: &[ClaimMapping]) -> BoxFuture<'_, DomainResult<()>> {
        // Project to owned tuples; reject any element missing a digest
        // before opening the transaction.
        let prepared: DomainResult<Vec<PreparedClaimMapping>> = items
            .iter()
            .map(|m| {
                let digest = m.managed_by_digest.ok_or_else(|| {
                    DomainError::Invariant(format!(
                        "save_managed requires managed_by_digest on claim_mapping {}",
                        m.id
                    ))
                })?;
                Ok(PreparedClaimMapping {
                    id: m.id,
                    idp_group: m.idp_group.clone(),
                    claim: m.claim.clone(),
                    digest: digest.to_vec(),
                })
            })
            .collect();
        Box::pin(async move {
            let prepared = prepared?;
            tracing::info!(
                entity = "claim_mapping",
                count = prepared.len(),
                "save_managed full reconcile (gitops apply)"
            );

            // Reconcile the ENTIRE `managed_by = 'gitops'` partition to
            // `items` in one transaction. `(idp_group, claim)` is the
            // table's UNIQUE key; delete-absent + upsert-present is
            // realised as delete-all-gitops + INSERT … ON CONFLICT.
            // `local` rows are out of scope. One tx → atomic; a failure
            // rolls the partition back unchanged.
            let mut tx = self.pool.begin().await.map_err(|e| {
                tracing::warn!(error = %e, "begin tx for claim_mappings save_managed");
                map_sqlx_error(&e, "ClaimMapping", "save_managed:begin")
            })?;

            sqlx::query("DELETE FROM claim_mappings WHERE managed_by = 'gitops'")
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "delete gitops-managed mappings");
                    map_sqlx_error(&e, "ClaimMapping", "save_managed:delete")
                })?;

            for m in &prepared {
                // ON CONFLICT guards the case where the same
                // (idp_group, claim) survives as a `local` row: the
                // gitops apply takes ownership of it (managed_by flips
                // to gitops — takes ownership of the surviving row.
                sqlx::query(
                    r#"INSERT INTO claim_mappings
                           (id, idp_group, claim, managed_by, managed_by_digest)
                       VALUES ($1, $2, $3, 'gitops', $4)
                       ON CONFLICT (idp_group, claim) DO UPDATE SET
                           managed_by        = 'gitops',
                           managed_by_digest = EXCLUDED.managed_by_digest"#,
                )
                .bind(m.id)
                .bind(&m.idp_group)
                .bind(&m.claim)
                .bind(&m.digest)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::warn!(mapping_id = %m.id, error = %e, "insert gitops mapping");
                    map_sqlx_error(&e, "ClaimMapping", &m.id.to_string())
                })?;
            }

            tx.commit().await.map_err(|e| {
                tracing::warn!(error = %e, "commit claim_mappings save_managed");
                map_sqlx_error(&e, "ClaimMapping", "save_managed:commit")
            })?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn sample_row() -> ClaimMappingRow {
        ClaimMappingRow {
            id: Uuid::from_u128(1),
            idp_group: "hort-admins".into(),
            claim: "admin".into(),
            managed_by: "local".into(),
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn row_to_claim_mapping_carries_all_fields() {
        let row = sample_row();
        let (id, g, c) = (row.id, row.idp_group.clone(), row.claim.clone());
        let m = row_to_claim_mapping(row);
        assert_eq!(m.id, id);
        assert_eq!(m.idp_group, g);
        assert_eq!(m.claim, c);
        assert_eq!(m.managed_by, ManagedBy::Local);
        assert!(m.managed_by_digest.is_none());
    }

    #[test]
    fn row_to_claim_mapping_gitops_round_trips() {
        let row = ClaimMappingRow {
            managed_by: "gitops".into(),
            managed_by_digest: Some(vec![0xab; 32]),
            ..sample_row()
        };
        let m = row_to_claim_mapping(row);
        assert_eq!(m.managed_by, ManagedBy::GitOps);
        assert_eq!(m.managed_by_digest, Some([0xab; 32]));
    }

    #[test]
    fn row_to_claim_mapping_unknown_managed_by_defaults_local() {
        let row = ClaimMappingRow {
            managed_by: "external".into(),
            ..sample_row()
        };
        let m = row_to_claim_mapping(row);
        assert_eq!(m.managed_by, ManagedBy::Local);
    }

    #[test]
    fn row_to_claim_mapping_wrong_digest_length_drops_digest() {
        let row = ClaimMappingRow {
            managed_by: "gitops".into(),
            managed_by_digest: Some(vec![0; 16]),
            ..sample_row()
        };
        let m = row_to_claim_mapping(row);
        assert!(m.managed_by_digest.is_none());
    }

    #[test]
    fn claim_mapping_repository_is_dyn_compatible() {
        let _ = size_of::<&dyn ClaimMappingRepository>();
    }

    #[tokio::test]
    async fn pg_claim_mapping_repo_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgClaimMappingRepository::new(pool);
    }

    // -- DB-backed integration tests (skipped when DATABASE_URL unset) ------

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

    // `save_managed` is the authoritative-set reconcile primitive
    // (delete-absent + upsert-present over the gitops partition, one
    // transaction). Deferred-execution: no `DATABASE_URL` here →
    // `maybe_pool` returns `None` and these early-return.

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_round_trips_and_is_idempotent() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgClaimMappingRepository::new(pool);
        let id = Uuid::new_v4();
        let group = format!("grp-{}", id.simple());
        let mapping = ClaimMapping {
            id,
            idp_group: group.clone(),
            claim: "developer".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0x33; 32]),
        };
        repo.save_managed(std::slice::from_ref(&mapping))
            .await
            .expect("save_managed");
        // Idempotent re-application of the same complete set on the
        // (idp_group, claim) key.
        repo.save_managed(std::slice::from_ref(&mapping))
            .await
            .expect("save_managed again (idempotent)");

        let all = repo.list_all().await.expect("list_all");
        let found = all
            .iter()
            .find(|m| m.idp_group == group && m.claim == "developer")
            .expect("mapping present");
        assert_eq!(found.managed_by, ManagedBy::GitOps);
        assert_eq!(found.managed_by_digest, Some([0x33; 32]));

        let managed = repo
            .list_managed_by_gitops()
            .await
            .expect("list_managed_by_gitops");
        assert_eq!(
            managed.iter().filter(|m| m.idp_group == group).count(),
            1,
            "idempotent re-apply must not duplicate the managed row"
        );
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_full_reconcile_deletes_absent_managed_rows() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgClaimMappingRepository::new(pool);
        let g1 = format!("grp-a-{}", Uuid::new_v4().simple());
        let g2 = format!("grp-b-{}", Uuid::new_v4().simple());
        let m_a = ClaimMapping {
            id: Uuid::new_v4(),
            idp_group: g1.clone(),
            claim: "developer".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0x01; 32]),
        };
        let m_b = ClaimMapping {
            id: Uuid::new_v4(),
            idp_group: g2.clone(),
            claim: "reader".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0x02; 32]),
        };
        repo.save_managed(&[m_a.clone(), m_b.clone()])
            .await
            .expect("first apply");

        // Reconcile to {m_a} — m_b must be revoked (delete-absent).
        repo.save_managed(std::slice::from_ref(&m_a))
            .await
            .expect("reconcile to {m_a}");

        let managed = repo
            .list_managed_by_gitops()
            .await
            .expect("list_managed_by_gitops");
        assert!(managed.iter().any(|m| m.idp_group == g1));
        assert!(
            !managed.iter().any(|m| m.idp_group == g2),
            "mapping absent from the new authoritative set must be deleted"
        );
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_empty_set_revokes_all_gitops_mappings() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = PgClaimMappingRepository::new(pool);
        let group = format!("grp-{}", Uuid::new_v4().simple());
        let mapping = ClaimMapping {
            id: Uuid::new_v4(),
            idp_group: group.clone(),
            claim: "developer".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0x33; 32]),
        };
        repo.save_managed(std::slice::from_ref(&mapping))
            .await
            .expect("seed one mapping");

        repo.save_managed(&[]).await.expect("reconcile to empty");

        let managed = repo
            .list_managed_by_gitops()
            .await
            .expect("list_managed_by_gitops");
        assert!(
            !managed.iter().any(|m| m.idp_group == group),
            "empty authoritative set revokes all gitops-managed mappings"
        );
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_managed_does_not_touch_local_rows() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let local_group = format!("local-{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO claim_mappings (id, idp_group, claim, managed_by) \
             VALUES ($1, $2, 'local-claim', 'local')",
        )
        .bind(Uuid::new_v4())
        .bind(&local_group)
        .execute(&pool)
        .await
        .expect("insert local mapping");

        let repo = PgClaimMappingRepository::new(pool.clone());
        repo.save_managed(&[])
            .await
            .expect("reconcile gitops empty");

        let all = repo.list_all().await.expect("list_all");
        assert!(
            all.iter().any(|m| m.idp_group == local_group),
            "Local row must survive a gitops-partition reconcile"
        );
    }
}
