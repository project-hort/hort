use std::collections::HashMap;

use sqlx::PgPool;
use uuid::Uuid;

use hort_domain::entities::artifact::ArtifactMetadata;
use hort_domain::error::DomainResult;
use hort_domain::ports::artifact_metadata_repository::ArtifactMetadataRepository;

use crate::event_store::PgUnitOfWork;
use crate::mappers::ArtifactMetadataRow;
use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`ArtifactMetadataRepository`].
///
/// Read-only trait impl — the write path is the inherent `upsert_in_tx`
/// method below, called from `PgArtifactLifecycle::commit_transition`
/// inside the lifecycle transaction (events → artifacts → artifact_metadata
/// lock order).
pub struct PgArtifactMetadataRepository {
    pool: PgPool,
}

impl PgArtifactMetadataRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const SELECT_COLS: &str = "artifact_id, format, metadata, metadata_blob, properties";

const UPSERT_SQL: &str = r#"
    INSERT INTO artifact_metadata (artifact_id, format, metadata, metadata_blob, properties)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (artifact_id) DO UPDATE SET
        format = EXCLUDED.format,
        metadata = EXCLUDED.metadata,
        metadata_blob = EXCLUDED.metadata_blob,
        properties = EXCLUDED.properties,
        updated_at = NOW()
"#;

impl ArtifactMetadataRepository for PgArtifactMetadataRepository {
    fn find_by_artifact_id(
        &self,
        artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Option<ArtifactMetadata>>> {
        Box::pin(async move {
            tracing::debug!(entity = "ArtifactMetadata", %artifact_id, "find_by_artifact_id");
            let sql = format!("SELECT {SELECT_COLS} FROM artifact_metadata WHERE artifact_id = $1");
            let row: Option<ArtifactMetadataRow> = sqlx::query_as(&sql)
                .bind(artifact_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ArtifactMetadata", &artifact_id.to_string()))?;
            row.map(ArtifactMetadata::try_from).transpose()
        })
    }

    fn list_by_artifact_ids(
        &self,
        ids: &[Uuid],
    ) -> BoxFuture<'_, DomainResult<HashMap<Uuid, ArtifactMetadata>>> {
        let ids: Vec<Uuid> = ids.to_vec();
        Box::pin(async move {
            tracing::debug!(
                entity = "ArtifactMetadata",
                count = ids.len(),
                "list_by_artifact_ids"
            );
            if ids.is_empty() {
                return Ok(HashMap::new());
            }
            let sql =
                format!("SELECT {SELECT_COLS} FROM artifact_metadata WHERE artifact_id = ANY($1)");
            let rows: Vec<ArtifactMetadataRow> = sqlx::query_as(&sql)
                .bind(&ids)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ArtifactMetadata", "list"))?;
            rows.into_iter()
                .map(|row| {
                    let id = row.artifact_id;
                    ArtifactMetadata::try_from(row).map(|m| (id, m))
                })
                .collect()
        })
    }
}

impl PgArtifactMetadataRepository {
    /// Upsert an `ArtifactMetadata` row within an existing transaction.
    ///
    /// Called from `PgArtifactLifecycle::commit_transition` between
    /// `save_in_tx` and `uow.commit()` — lock order is events → artifacts →
    /// artifact_metadata. Not exposed on the trait: the port stays
    /// read-only; the only write path runs through the lifecycle port.
    pub(crate) async fn upsert_in_tx(
        &self,
        tx: &mut PgUnitOfWork,
        m: &ArtifactMetadata,
    ) -> DomainResult<()> {
        tracing::debug!(
            entity = "ArtifactMetadata",
            artifact_id = %m.artifact_id,
            "upsert_in_tx"
        );
        // NB: deliberately no blob-hash value in the log — hashes aren't
        // secret but logging them makes trivial correlation work for any
        // attacker who gets log access (same rule as `sha256_checksum`).
        let metadata_blob: Option<String> = m.metadata_blob.as_ref().map(ToString::to_string);
        sqlx::query(UPSERT_SQL)
            .bind(m.artifact_id)
            .bind(m.format.to_string())
            .bind(&m.metadata)
            .bind(metadata_blob)
            .bind(&m.properties)
            .execute(tx.conn())
            .await
            .map_err(|e| map_sqlx_error(&e, "ArtifactMetadata", &m.artifact_id.to_string()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests — row mapping + error mapping. Integration tests against real
// Postgres run under Item 4's E2E harness; here we cover the pure pieces.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::error::DomainError;

    const VALID_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn row_for(format: &str) -> ArtifactMetadataRow {
        ArtifactMetadataRow {
            artifact_id: Uuid::nil(),
            format: format.into(),
            metadata: serde_json::json!({"requires_python": ">=3.8"}),
            metadata_blob: None,
            properties: serde_json::json!({}),
        }
    }

    #[test]
    fn row_converts_known_format() {
        let row = row_for("pypi");
        let meta = ArtifactMetadata::try_from(row).unwrap();
        assert_eq!(meta.format, RepositoryFormat::Pypi);
        assert_eq!(meta.artifact_id, Uuid::nil());
        assert_eq!(meta.metadata["requires_python"], "\u{003e}=3.8");
    }

    #[test]
    fn row_converts_unknown_format_to_other() {
        let row = row_for("flatpak");
        let meta = ArtifactMetadata::try_from(row).unwrap();
        assert_eq!(meta.format, RepositoryFormat::Other("flatpak".into()));
    }

    /// Happy path — Inline strategy: `metadata_blob` column is NULL, domain
    /// entity carries `None`. This is the shape the port produces for every
    /// Inline format and for HashReference payloads under threshold.
    #[test]
    fn row_maps_absent_blob_to_none() {
        let row = row_for("pypi");
        let meta = ArtifactMetadata::try_from(row).unwrap();
        assert!(meta.metadata_blob.is_none());
    }

    /// Happy path — HashReference strategy: a valid 64-char lowercase hex
    /// string round-trips into `Some(ContentHash)` with the same bytes.
    #[test]
    fn row_maps_present_blob_to_content_hash() {
        let row = ArtifactMetadataRow {
            metadata_blob: Some(VALID_HASH.into()),
            ..row_for("npm")
        };
        let meta = ArtifactMetadata::try_from(row).unwrap();
        let hash = meta.metadata_blob.expect("expected Some(ContentHash)");
        assert_eq!(hash.as_ref(), VALID_HASH);
    }

    /// Defence-in-depth — a corrupt hex string in the DB (not possible
    /// via our write path; covers direct SQL, operator repair, malicious
    /// tampering) surfaces as `DomainError::Invariant`, not as a silent
    /// `None` or a panic.
    #[test]
    fn row_maps_malformed_blob_to_invariant() {
        let row = ArtifactMetadataRow {
            metadata_blob: Some("not-a-valid-sha256".into()),
            ..row_for("npm")
        };
        let err = ArtifactMetadata::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("corrupt metadata_blob"));
    }

    /// `map_sqlx_error` is the shared error-mapping hook exercised by every
    /// query in this adapter. Confirm the branches that matter for the two
    /// port methods: `RowNotFound` → `DomainError::NotFound`, duplicate-key
    /// text → `Conflict`, anything else → `Invariant`.
    #[test]
    fn error_mapping_row_not_found() {
        let e = sqlx::Error::RowNotFound;
        let mapped = map_sqlx_error(&e, "ArtifactMetadata", "abc");
        assert!(matches!(
            mapped,
            DomainError::NotFound {
                entity: "ArtifactMetadata",
                ..
            }
        ));
    }

    #[test]
    fn error_mapping_duplicate_key_is_conflict() {
        // sqlx::Error::Protocol is a stringly-typed variant we can construct
        // without a real Postgres connection — and its Display includes the
        // message, which is what map_sqlx_error inspects.
        let e = sqlx::Error::Protocol("duplicate key value violates unique constraint".into());
        let mapped = map_sqlx_error(&e, "ArtifactMetadata", "abc");
        assert!(matches!(mapped, DomainError::Conflict(_)));
    }

    #[test]
    fn error_mapping_other_is_invariant() {
        let e = sqlx::Error::Protocol("some other failure".into());
        let mapped = map_sqlx_error(&e, "ArtifactMetadata", "abc");
        assert!(matches!(mapped, DomainError::Invariant(_)));
    }
}
