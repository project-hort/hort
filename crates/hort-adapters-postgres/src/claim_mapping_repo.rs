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
/// the reconcile transaction opens so the future borrows nothing
/// from `items`. Named struct (not a 4-tuple) to keep the reconcile
/// INSERT loop readable and to satisfy `clippy::type_complexity` —
/// behaviour is identical to the prior tuple form.
pub(crate) struct PreparedClaimMapping {
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
            let rows: Vec<ClaimMappingRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
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
            let rows: Vec<ClaimMappingRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ClaimMapping", "list_managed_by_gitops"))?;
            Ok(rows.into_iter().map(row_to_claim_mapping).collect())
        })
    }
}

// ---------------------------------------------------------------------------
// In-transaction reconcile — shared with the authority lifecycle adapter
// ---------------------------------------------------------------------------

/// Project a managed mapping set to its owned column tuples, rejecting
/// any element missing a digest **before** a transaction is opened.
pub(crate) fn prepare_managed_claim_mappings(
    items: &[ClaimMapping],
) -> DomainResult<Vec<PreparedClaimMapping>> {
    items
        .iter()
        .map(|m| {
            let digest = m.managed_by_digest.ok_or_else(|| {
                DomainError::Invariant(format!(
                    "a managed claim_mapping requires managed_by_digest, mapping {} has none",
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
        .collect()
}

/// Reconcile the ENTIRE `managed_by = 'gitops'` partition to `prepared`
/// on the caller's open transaction.
///
/// `(idp_group, claim)` is the table's UNIQUE key; delete-absent +
/// upsert-present is realised as delete-all-gitops + INSERT … ON
/// CONFLICT. `local` rows are out of scope.
///
/// The caller owns the transaction boundary, which is what lets the
/// audit append join the same transaction
/// (`crate::authority_lifecycle::PgAuthorityLifecycle`); a failure on
/// either side rolls the partition back unchanged.
pub(crate) async fn reconcile_managed_claim_mappings_in_tx(
    conn: &mut sqlx::PgConnection,
    prepared: &[PreparedClaimMapping],
) -> DomainResult<()> {
    tracing::info!(
        entity = "claim_mapping",
        count = prepared.len(),
        "managed-partition full reconcile (gitops apply)"
    );

    sqlx::query("DELETE FROM claim_mappings WHERE managed_by = 'gitops'")
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "delete gitops-managed mappings");
            map_sqlx_error(&e, "ClaimMapping", "reconcile_managed:delete")
        })?;

    for m in prepared {
        // ON CONFLICT guards the case where the same
        // (idp_group, claim) survives as a `local` row: the gitops
        // apply takes ownership of the surviving row (managed_by flips
        // to gitops).
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
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::warn!(mapping_id = %m.id, error = %e, "insert gitops mapping");
            map_sqlx_error(&e, "ClaimMapping", &m.id.to_string())
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
