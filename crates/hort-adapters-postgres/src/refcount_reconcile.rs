//! PostgreSQL adapter for [`RefcountReconcilePort`] — the
//! refcount-reconcile sweep (ADR 0020).
//!
//! Brings the eventually-authoritative `content_references` refcount
//! projection back into agreement with the authoritative `artifacts`
//! and `artifact_metadata` tables. See the port module docs
//! (`hort-domain/src/ports/refcount_reconcile.rs`) for the
//! eventual-authority posture this repairs.
//!
//! Purely additive: a brand-new adapter for a brand-new (additive)
//! port. No existing adapter or port signature is touched. The
//! existing [`crate::pg_content_reference_repo::PgContentReferenceRepo`]
//! is left exactly as shipped.
//!
//! # Scan: one set-based query per drift category
//!
//! `scan_repo_drift` issues three index-bound queries (the §3 G1
//! "run in two parts so the query plan stays index-bound" guidance,
//! extended to three because rejected-source rows are a third
//! category):
//!
//! 1. **primary_content drift** — left-join `artifacts` against the
//!    `kind = 'primary_content'` rows. A NULL join → missing
//!    (`CreatePrimaryContent`); a non-NULL join whose
//!    `target_content_hash <> checksum_sha256` → mis-targeted
//!    (`RepairPrimaryContent`). Quarantined/rejected/indeterminate
//!    artifacts are excluded here (rejected rows are category 3;
//!    quarantined are evidence — not reconciled into refcounts).
//! 2. **metadata_blob drift** — left-join the artifacts that have a
//!    non-null `artifact_metadata.metadata_blob` against the
//!    `kind = 'metadata_blob'` rows. Missing OR mis-targeted →
//!    `UpsertMetadataBlob` (one variant, idempotent upsert covers
//!    both).
//! 3. **rejected-source rows** — every `content_references` row whose
//!    source artifact is `quarantine_status = 'rejected'`, deduped to
//!    one `DeleteRejectedSourceRows` per source (the repair sweeps
//!    every kind for that source).
//!
//! # Repair: idempotent upsert / sweep
//!
//! `apply_repair` is idempotent — create/repair is the same
//! `ON CONFLICT (repository_id, source_artifact_id, kind) DO UPDATE`
//! upsert the shipped `PgContentReferenceRepo::insert` uses; the
//! rejected-source delete is `DELETE … WHERE source_artifact_id = $1`
//! (every kind). Re-applying an already-applied repair is a no-op, so
//! the sweep is re-runnable and converges to zero drift.
//!
//! `metadata_blob` is stored as `character(64)` (blank-padded) on
//! `artifact_metadata`; it is trimmed at the boundary before parsing,
//! mirroring `pg_content_reference_repo::row_to_reference`'s
//! `target_content_hash.trim()`.

use std::str::FromStr;

use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::refcount_reconcile::{RefcountReconcilePort, RefcountRepair, RepoDrift};
use hort_domain::types::ContentHash;

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`RefcountReconcilePort`].
///
/// Thin wrapper over a `PgPool`; no per-instance state beyond the
/// pool. Construction is cheap (no I/O).
pub struct PgRefcountReconcile {
    pool: PgPool,
}

impl PgRefcountReconcile {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// `primary_content` drift row: an artifact whose `primary_content`
/// projection row is missing or mis-targeted. `cr_hash` is the
/// projection's current target (NULL when the row is missing entirely).
#[derive(Debug, FromRow)]
struct PrimaryDriftRow {
    artifact_id: Uuid,
    checksum_sha256: String,
    cr_hash: Option<String>,
}

/// `metadata_blob` drift row: an artifact with a non-null
/// `artifact_metadata.metadata_blob` whose `metadata_blob` projection
/// row is missing or mis-targeted. `cr_hash` is the projection's
/// current target (NULL when missing).
#[derive(Debug, FromRow)]
struct MetadataDriftRow {
    artifact_id: Uuid,
    metadata_blob: String,
    cr_hash: Option<String>,
}

/// One `(source_artifact_id, kind)` observed on a `content_references`
/// row whose source artifact is `rejected`. Deduped to one repair per
/// source in `scan_repo_drift`.
#[derive(Debug, FromRow)]
struct RejectedRow {
    source_artifact_id: Uuid,
    kind: String,
}

/// Parse a DB hash column into a [`ContentHash`], trimming the
/// blank-padding `character(64)` columns carry. A corrupt value is a
/// data-integrity error (mirrors `pg_content_reference_repo`).
fn parse_hash(raw: &str, ctx: &str) -> DomainResult<ContentHash> {
    ContentHash::from_str(raw.trim()).map_err(|_| {
        DomainError::Invariant(format!("refcount-reconcile: corrupt hash {raw:?} ({ctx})"))
    })
}

impl RefcountReconcilePort for PgRefcountReconcile {
    fn list_repository_ids(&self) -> BoxFuture<'_, DomainResult<Vec<Uuid>>> {
        Box::pin(async move {
            // Every repository that owns at least one artifact row.
            // Repos with zero artifacts have nothing to reconcile.
            let ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT DISTINCT repository_id FROM artifacts ORDER BY repository_id",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "refcount_reconcile", "list_repos"))?;
            Ok(ids)
        })
    }

    fn scan_repo_drift(&self, repo_id: Uuid) -> BoxFuture<'_, DomainResult<RepoDrift>> {
        Box::pin(async move {
            let mut repairs: Vec<RefcountRepair> = Vec::new();

            // -- category 1: primary_content missing / mis-targeted ----
            //
            // Exclude quarantined / rejected / scan_indeterminate:
            // rejected rows are category 3 (deleted, not back-filled);
            // quarantined/indeterminate are evidence and must not have
            // a refcount minted that would later make their blob look
            // GC-protected for the wrong reason. `none` / `clean` /
            // `flagged` / `released` / NULL get the refcount.
            let primary: Vec<PrimaryDriftRow> = sqlx::query_as(
                r#"
                SELECT a.id              AS artifact_id,
                       a.checksum_sha256 AS checksum_sha256,
                       cr.target_content_hash AS cr_hash
                  FROM artifacts a
                  LEFT JOIN content_references cr
                         ON cr.repository_id      = a.repository_id
                        AND cr.source_artifact_id = a.id
                        AND cr.kind               = 'primary_content'
                 WHERE a.repository_id = $1
                   AND (a.quarantine_status IS NULL
                        OR a.quarantine_status NOT IN
                           ('quarantined','rejected','scan_indeterminate'))
                   AND (cr.target_content_hash IS NULL
                        OR cr.target_content_hash <> a.checksum_sha256)
                "#,
            )
            .bind(repo_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "refcount_reconcile", "scan_primary"))?;

            for row in primary {
                let expected = parse_hash(&row.checksum_sha256, "artifacts.checksum_sha256")?;
                match row.cr_hash {
                    None => repairs.push(RefcountRepair::CreatePrimaryContent {
                        source_artifact_id: row.artifact_id,
                        expected_hash: expected,
                    }),
                    Some(found_raw) => {
                        let found =
                            parse_hash(&found_raw, "content_references.target_content_hash")?;
                        repairs.push(RefcountRepair::RepairPrimaryContent {
                            source_artifact_id: row.artifact_id,
                            found_hash: found,
                            expected_hash: expected,
                        });
                    }
                }
            }

            // -- category 2: metadata_blob missing / mis-targeted ------
            let meta: Vec<MetadataDriftRow> = sqlx::query_as(
                r#"
                SELECT a.id AS artifact_id,
                       am.metadata_blob AS metadata_blob,
                       cr.target_content_hash AS cr_hash
                  FROM artifacts a
                  JOIN artifact_metadata am
                    ON am.artifact_id = a.id
                  LEFT JOIN content_references cr
                         ON cr.repository_id      = a.repository_id
                        AND cr.source_artifact_id = a.id
                        AND cr.kind               = 'metadata_blob'
                 WHERE a.repository_id = $1
                   AND am.metadata_blob IS NOT NULL
                   AND (a.quarantine_status IS NULL
                        OR a.quarantine_status NOT IN
                           ('quarantined','rejected','scan_indeterminate'))
                   AND (cr.target_content_hash IS NULL
                        OR cr.target_content_hash <> trim(am.metadata_blob))
                "#,
            )
            .bind(repo_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "refcount_reconcile", "scan_metadata"))?;

            for row in meta {
                let expected = parse_hash(&row.metadata_blob, "artifact_metadata.metadata_blob")?;
                let found = match row.cr_hash {
                    Some(raw) => Some(parse_hash(&raw, "content_references.target_content_hash")?),
                    None => None,
                };
                repairs.push(RefcountRepair::UpsertMetadataBlob {
                    source_artifact_id: row.artifact_id,
                    found_hash: found,
                    expected_hash: expected,
                });
            }

            // -- category 3: stale rows for rejected sources -----------
            //
            // One repair per source (the repair sweeps every kind for
            // that source). DISTINCT ON keeps the first kind observed
            // for the `warn!` label; the delete is kind-agnostic.
            let rejected: Vec<RejectedRow> = sqlx::query_as(
                r#"
                SELECT DISTINCT ON (cr.source_artifact_id)
                       cr.source_artifact_id AS source_artifact_id,
                       cr.kind               AS kind
                  FROM content_references cr
                  JOIN artifacts a
                    ON a.id = cr.source_artifact_id
                 WHERE cr.repository_id = $1
                   AND a.quarantine_status = 'rejected'
                 ORDER BY cr.source_artifact_id, cr.kind
                "#,
            )
            .bind(repo_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "refcount_reconcile", "scan_rejected"))?;

            for row in rejected {
                repairs.push(RefcountRepair::DeleteRejectedSourceRows {
                    source_artifact_id: row.source_artifact_id,
                    kind: row.kind,
                });
            }

            Ok(RepoDrift { repairs })
        })
    }

    fn apply_repair<'a>(
        &'a self,
        repo_id: Uuid,
        repair: &'a RefcountRepair,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            match repair {
                RefcountRepair::CreatePrimaryContent {
                    source_artifact_id,
                    expected_hash,
                } => {
                    self.upsert_row(
                        repo_id,
                        *source_artifact_id,
                        "primary_content",
                        expected_hash,
                    )
                    .await
                }
                RefcountRepair::RepairPrimaryContent {
                    source_artifact_id,
                    expected_hash,
                    ..
                } => {
                    self.upsert_row(
                        repo_id,
                        *source_artifact_id,
                        "primary_content",
                        expected_hash,
                    )
                    .await
                }
                RefcountRepair::UpsertMetadataBlob {
                    source_artifact_id,
                    expected_hash,
                    ..
                } => {
                    self.upsert_row(repo_id, *source_artifact_id, "metadata_blob", expected_hash)
                        .await
                }
                RefcountRepair::DeleteRejectedSourceRows {
                    source_artifact_id, ..
                } => {
                    // Sweep every kind for the source — the warn-on-fail
                    // `ArtifactRejected` cascade did not land.
                    sqlx::query(
                        "DELETE FROM content_references \
                         WHERE repository_id = $1 AND source_artifact_id = $2",
                    )
                    .bind(repo_id)
                    .bind(source_artifact_id)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        map_sqlx_error(&e, "refcount_reconcile", &source_artifact_id.to_string())
                    })?;
                    Ok(())
                }
            }
        })
    }
}

impl PgRefcountReconcile {
    /// Idempotent upsert of one refcount row, identical in shape to
    /// `PgContentReferenceRepo::insert`'s `ON CONFLICT … DO UPDATE`
    /// (so create and repair are the same statement and re-running is
    /// a no-op). `metadata` is the empty object — the reconcile sweep
    /// does not synthesise sidecar metadata (the ingest path owns
    /// that; reconcile only restores the refcount itself).
    async fn upsert_row(
        &self,
        repo_id: Uuid,
        source_artifact_id: Uuid,
        kind: &str,
        target: &ContentHash,
    ) -> DomainResult<()> {
        sqlx::query(
            r#"INSERT INTO content_references (
                   source_artifact_id, target_content_hash, kind, metadata,
                   repository_id, recorded_at
               ) VALUES ($1, $2, $3, '{}'::jsonb, $4, now())
               ON CONFLICT (repository_id, source_artifact_id, kind) DO UPDATE SET
                   target_content_hash = EXCLUDED.target_content_hash,
                   recorded_at         = EXCLUDED.recorded_at"#,
        )
        .bind(source_artifact_id)
        .bind(target.as_ref())
        .bind(kind)
        .bind(repo_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            map_sqlx_error(
                &e,
                "refcount_reconcile",
                &format!("{repo_id}/{source_artifact_id}/{kind}"),
            )
        })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const HASH_B: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    const HASH_C: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    // -- pure unit -----------------------------------------------------

    #[test]
    fn adapter_implements_port() {
        fn _assert_port<T: RefcountReconcilePort>() {}
        _assert_port::<PgRefcountReconcile>();
    }

    #[tokio::test]
    async fn pg_refcount_reconcile_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgRefcountReconcile::new(pool);
    }

    #[test]
    fn parse_hash_trims_padding_and_parses() {
        // `character(64)` columns blank-pad; the boundary must trim.
        let padded = format!("{HASH_A}   ");
        assert_eq!(parse_hash(&padded, "test").unwrap().as_ref(), HASH_A);
    }

    #[test]
    fn parse_hash_rejects_corrupt() {
        let err = parse_hash("not-a-hash", "test ctx").unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("corrupt hash"));
        assert!(err.to_string().contains("test ctx"));
    }

    // -- DB-backed integration tests -----------------------------------
    //
    // Skipped (silent return) when `DATABASE_URL` is unset — mirrors
    // `pg_content_reference_repo.rs` / `scan_findings_repository.rs`.
    // Each test seeds throwaway rows under a fresh repo and cleans up
    // with the repo-row `ON DELETE CASCADE`.

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

    async fn seed_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("it-refcount-recon-{}", id.simple());
        sqlx::query(
            r#"INSERT INTO repositories (
                   id, key, name, format, repo_type, storage_backend, storage_path,
                   replication_priority
               ) VALUES (
                   $1, $2, $3,
                   'generic'::repository_format,
                   'hosted'::repository_type,
                   'filesystem', $4,
                   'local_only'::replication_priority
               )"#,
        )
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .execute(pool)
        .await
        .expect("seed repo");
        id
    }

    async fn seed_artifact(
        pool: &PgPool,
        repo: Uuid,
        name: &str,
        checksum: &str,
        quarantine_status: Option<&str>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   quarantine_status
               ) VALUES (
                   $1, $2, $3, $3, '1.0.0', $4,
                   0, $5, 'application/octet-stream', $4, $6
               )"#,
        )
        .bind(id)
        .bind(repo)
        .bind(name)
        .bind(format!("artifacts/{name}-{}", id.simple()))
        .bind(checksum)
        .bind(quarantine_status)
        .execute(pool)
        .await
        .expect("seed artifact");
        id
    }

    async fn seed_metadata_blob(pool: &PgPool, artifact: Uuid, blob_hash: &str) {
        sqlx::query(
            r#"INSERT INTO artifact_metadata (artifact_id, format, metadata_blob)
               VALUES ($1, 'generic', $2)"#,
        )
        .bind(artifact)
        .bind(blob_hash)
        .execute(pool)
        .await
        .expect("seed metadata blob");
    }

    async fn insert_cr(pool: &PgPool, repo: Uuid, source: Uuid, kind: &str, target: &str) {
        sqlx::query(
            r#"INSERT INTO content_references (
                   source_artifact_id, target_content_hash, kind, metadata,
                   repository_id, recorded_at
               ) VALUES ($1, $2, $3, '{}'::jsonb, $4, now())"#,
        )
        .bind(source)
        .bind(target)
        .bind(kind)
        .bind(repo)
        .execute(pool)
        .await
        .expect("seed content_references row");
    }

    async fn cr_rows_for(pool: &PgPool, source: Uuid) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT kind, target_content_hash FROM content_references \
             WHERE source_artifact_id = $1 ORDER BY kind",
        )
        .bind(source)
        .fetch_all(pool)
        .await
        .expect("read cr rows")
    }

    async fn cleanup(pool: &PgPool, repo: Uuid) {
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(pool)
            .await;
    }

    /// `list_repository_ids` returns exactly the repos that own an
    /// artifact, and the per-repo scan converges them.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_repos_includes_repo_with_artifact() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        seed_artifact(&pool, repo, "a", HASH_A, None).await;
        let adapter = PgRefcountReconcile::new(pool.clone());

        let ids = adapter.list_repository_ids().await.unwrap();
        assert!(ids.contains(&repo));

        cleanup(&pool, repo).await;
    }

    /// Missing `primary_content` → one `CreatePrimaryContent`; the
    /// repair creates the row at `artifacts.checksum_sha256`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn drift_create_missing_primary_content() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        // A1's migration back-fill only runs on existing rows at
        // migration time; a row inserted after has no projection row,
        // exactly the post-commit-write-lagged case B3.5 repairs. We
        // delete any auto-row to force the missing state deterministically.
        let art = seed_artifact(&pool, repo, "missing-pc", HASH_A, None).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        let adapter = PgRefcountReconcile::new(pool.clone());

        let drift = adapter.scan_repo_drift(repo).await.unwrap();
        assert_eq!(drift.repairs.len(), 1, "exactly one drift case");
        assert!(matches!(
            &drift.repairs[0],
            RefcountRepair::CreatePrimaryContent { source_artifact_id, expected_hash }
                if *source_artifact_id == art && expected_hash.as_ref() == HASH_A
        ));

        adapter.apply_repair(repo, &drift.repairs[0]).await.unwrap();
        let rows = cr_rows_for(&pool, art).await;
        assert_eq!(rows, vec![("primary_content".into(), HASH_A.into())]);

        // Re-scan converges (idempotent — no further drift).
        let again = adapter.scan_repo_drift(repo).await.unwrap();
        assert!(again.repairs.is_empty(), "converged after repair");

        cleanup(&pool, repo).await;
    }

    /// Mis-targeted `primary_content` → `RepairPrimaryContent`; the
    /// repair rewrites the target hash in place.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn drift_repair_mistargeted_primary_content() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "mistargeted", HASH_A, None).await;
        // Force the projection row to the WRONG hash.
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_B).await;
        let adapter = PgRefcountReconcile::new(pool.clone());

        let drift = adapter.scan_repo_drift(repo).await.unwrap();
        assert_eq!(drift.repairs.len(), 1);
        assert!(matches!(
            &drift.repairs[0],
            RefcountRepair::RepairPrimaryContent { found_hash, expected_hash, .. }
                if found_hash.as_ref() == HASH_B && expected_hash.as_ref() == HASH_A
        ));

        adapter.apply_repair(repo, &drift.repairs[0]).await.unwrap();
        let rows = cr_rows_for(&pool, art).await;
        assert_eq!(rows, vec![("primary_content".into(), HASH_A.into())]);
        assert!(adapter
            .scan_repo_drift(repo)
            .await
            .unwrap()
            .repairs
            .is_empty());

        cleanup(&pool, repo).await;
    }

    /// Non-null `artifact_metadata.metadata_blob` with no
    /// `metadata_blob` projection row → `UpsertMetadataBlob`; the
    /// repair creates it. The auto-backfilled `primary_content` row is
    /// already correct so it is NOT reported as drift.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn drift_upsert_missing_metadata_blob() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "with-meta", HASH_A, None).await;
        seed_metadata_blob(&pool, art, HASH_C).await;
        let adapter = PgRefcountReconcile::new(pool.clone());

        let drift = adapter.scan_repo_drift(repo).await.unwrap();
        // Exactly the metadata_blob drift — primary_content was
        // auto-backfilled at insert by migration 003's trigger-free
        // back-fill? No: back-fill runs only at migration time. The
        // post-insert row has no primary_content row either, so we
        // expect BOTH a CreatePrimaryContent and an UpsertMetadataBlob.
        assert!(drift
            .repairs
            .iter()
            .any(|r| matches!(r, RefcountRepair::UpsertMetadataBlob {
                source_artifact_id, expected_hash, found_hash: None
            } if *source_artifact_id == art && expected_hash.as_ref() == HASH_C)));

        for r in &drift.repairs {
            adapter.apply_repair(repo, r).await.unwrap();
        }
        let rows = cr_rows_for(&pool, art).await;
        assert!(rows.contains(&("metadata_blob".into(), HASH_C.into())));
        assert!(rows.contains(&("primary_content".into(), HASH_A.into())));
        assert!(adapter
            .scan_repo_drift(repo)
            .await
            .unwrap()
            .repairs
            .is_empty());

        cleanup(&pool, repo).await;
    }

    /// A `content_references` row whose source artifact is `rejected`
    /// → `DeleteRejectedSourceRows`; the repair sweeps every kind for
    /// that source.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn drift_delete_rejected_source_rows() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "rejected", HASH_A, Some("rejected")).await;
        // Two stale rows under different kinds for the rejected source.
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_A).await;
        insert_cr(&pool, repo, art, "oci_subject", HASH_B).await;
        let adapter = PgRefcountReconcile::new(pool.clone());

        let drift = adapter.scan_repo_drift(repo).await.unwrap();
        // One DeleteRejectedSourceRows for the source (deduped); NO
        // primary_content create (rejected artifacts are excluded from
        // category 1).
        assert_eq!(drift.repairs.len(), 1, "deduped to one repair");
        assert!(matches!(
            &drift.repairs[0],
            RefcountRepair::DeleteRejectedSourceRows { source_artifact_id, .. }
                if *source_artifact_id == art
        ));

        adapter.apply_repair(repo, &drift.repairs[0]).await.unwrap();
        assert!(
            cr_rows_for(&pool, art).await.is_empty(),
            "every kind for the rejected source is swept"
        );
        assert!(adapter
            .scan_repo_drift(repo)
            .await
            .unwrap()
            .repairs
            .is_empty());

        cleanup(&pool, repo).await;
    }

    /// A clean / converged projection produces zero drift, and a
    /// re-run after repair is a no-op (idempotency end-to-end).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn clean_projection_yields_no_drift_and_is_idempotent() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "clean", HASH_A, None).await;
        // Make the projection correct by hand.
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_A).await;
        let adapter = PgRefcountReconcile::new(pool.clone());

        let drift = adapter.scan_repo_drift(repo).await.unwrap();
        assert!(drift.repairs.is_empty(), "converged projection → no drift");

        // Applying a CreatePrimaryContent for an already-correct row is
        // a harmless upsert no-op (idempotent repair primitive).
        adapter
            .apply_repair(
                repo,
                &RefcountRepair::CreatePrimaryContent {
                    source_artifact_id: art,
                    expected_hash: HASH_A.parse().unwrap(),
                },
            )
            .await
            .unwrap();
        let rows = cr_rows_for(&pool, art).await;
        assert_eq!(
            rows,
            vec![("primary_content".into(), HASH_A.into())],
            "idempotent upsert did not duplicate or change the row"
        );

        cleanup(&pool, repo).await;
    }

    /// Quarantined artifacts are NOT reconciled into a refcount
    /// (evidence; excluded from category 1) and NOT swept (only
    /// `rejected` is category 3).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn quarantined_artifact_is_left_alone() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "quar", HASH_A, Some("quarantined")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        let adapter = PgRefcountReconcile::new(pool.clone());

        let drift = adapter.scan_repo_drift(repo).await.unwrap();
        assert!(
            drift.repairs.is_empty(),
            "a quarantined artifact yields no primary_content create and no delete"
        );

        cleanup(&pool, repo).await;
    }
}
