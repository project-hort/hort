//! PostgreSQL adapter for [`ContentReferenceIndex`].
//!
//! Implements the content-reference projection. One row per
//! `(repository_id, source_artifact_id, kind)`. The same source artifact
//! may carry rows of different `kind` simultaneously — e.g. an OCI
//! manifest carries an `oci_subject` row (its `subject.digest`) AND a
//! `primary_content` row (its own SHA-256). Lookup by target content
//! hash is a direct btree hit via `idx_content_references_target`.
//!
//! # `kind` values in scope today
//!
//! - `"oci_subject"` — OCI Referrers projection. Seeded by the OCI
//!   manifest-write path on every PUT that carries a `subject.digest`.
//! - `"primary_content"` — refcount row. Written for every
//!   `ArtifactIngested` so the GC-eligibility query can prove a blob
//!   is unreferenced.
//! - `"metadata_blob"` — HashReference-strategy row. Written when an
//!   `ArtifactIngested` payload includes a CAS-resident metadata blob.
//! - `"wheel_metadata"` — PEP 658 wheel METADATA file bytes —
//!   extracted from the wheel's `<dist-info>/METADATA` member during
//!   ingest, linked back to the parent wheel artifact, and served by
//!   `GET …/files/<wheel>.metadata`. Kept in lockstep with the domain
//!   port's "Allocated kind values" list ([`ContentReferenceIndex`]
//!   docstring).
//!
//! # Upsert semantics
//!
//! `insert` runs
//!
//! ```sql
//! INSERT INTO content_references (...)
//! VALUES (...)
//! ON CONFLICT (repository_id, source_artifact_id, kind) DO UPDATE SET
//!     target_content_hash = EXCLUDED.target_content_hash,
//!     metadata            = EXCLUDED.metadata,
//!     recorded_at         = EXCLUDED.recorded_at
//! ```
//!
//! Idempotent re-ingest of the same source under the same kind (the OCI
//! manifest-PUT retry) refreshes the row rather than tripping a
//! unique-constraint violation. Inserting the same source under a
//! *different* kind adds a sibling row — the refcount design requires
//! this.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::types::ContentHash;

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`ContentReferenceIndex`].
///
/// Thin wrapper over a `PgPool`; no per-instance state beyond the pool.
/// Construction is cheap (no I/O) — the pool itself governs connection
/// lifecycle.
pub struct PgContentReferenceRepo {
    pool: PgPool,
}

impl PgContentReferenceRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// SQL fragment selecting every column needed to build a
/// [`ContentReference`]. Kept at module scope so the `INSERT ...
/// RETURNING` path and the `SELECT` path share one spelling.
const SELECT_COLS: &str = r#"
    source_artifact_id, target_content_hash, kind, metadata,
    repository_id, recorded_at
"#;

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

/// Wire shape for a `content_references` row. The `target_content_hash`
/// column stores the raw 64-char lowercase hex form of SHA-256, matching
/// every other `ContentHash`-typed column (see
/// `artifacts.checksum_sha256`). Translation to [`ContentHash`] is
/// fallible because a corrupt hex string is a data-integrity error.
#[derive(Debug, FromRow)]
struct ContentReferenceRow {
    source_artifact_id: Uuid,
    target_content_hash: String,
    kind: String,
    metadata: serde_json::Value,
    repository_id: Uuid,
    recorded_at: DateTime<Utc>,
}

fn row_to_reference(row: ContentReferenceRow) -> DomainResult<ContentReference> {
    let target_content_hash =
        ContentHash::from_str(row.target_content_hash.trim()).map_err(|_| {
            DomainError::Invariant(format!(
                "corrupt target_content_hash in content_references row \
                 (repo={repo}, source={source}): {raw:?}",
                repo = row.repository_id,
                source = row.source_artifact_id,
                raw = row.target_content_hash,
            ))
        })?;
    Ok(ContentReference {
        source_artifact_id: row.source_artifact_id,
        target_content_hash,
        kind: row.kind,
        metadata: row.metadata,
        repository_id: row.repository_id,
        recorded_at: row.recorded_at,
    })
}

// ---------------------------------------------------------------------------
// Port impl
// ---------------------------------------------------------------------------

impl ContentReferenceIndex for PgContentReferenceRepo {
    fn insert(&self, reference: ContentReference) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "ContentReference",
                repository_id = %reference.repository_id,
                source_artifact_id = %reference.source_artifact_id,
                target_content_hash = %reference.target_content_hash,
                kind = %reference.kind,
                "insert"
            );
            // Upsert on the PK so idempotent source re-push is a
            // refresh, not a 409 — see module docs. The caller
            // typically supplies `Utc::now()` but tests / replay may
            // set `recorded_at` explicitly.
            let target_hex = reference.target_content_hash.as_ref().to_owned();
            sqlx::query(
                r#"INSERT INTO content_references (
                       source_artifact_id, target_content_hash, kind, metadata,
                       repository_id, recorded_at
                   ) VALUES ($1, $2, $3, $4, $5, $6)
                   ON CONFLICT (repository_id, source_artifact_id, kind) DO UPDATE SET
                       target_content_hash = EXCLUDED.target_content_hash,
                       metadata            = EXCLUDED.metadata,
                       recorded_at         = EXCLUDED.recorded_at"#,
            )
            .bind(reference.source_artifact_id)
            .bind(&target_hex)
            .bind(&reference.kind)
            .bind(&reference.metadata)
            .bind(reference.repository_id)
            .bind(reference.recorded_at)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                map_sqlx_error(
                    &e,
                    "ContentReference",
                    &format!(
                        "{}/{}",
                        reference.repository_id, reference.source_artifact_id
                    ),
                )
            })?;
            Ok(())
        })
    }

    fn find_by_target(
        &self,
        repo: Uuid,
        target: &ContentHash,
        kind_filter: Option<&str>,
    ) -> BoxFuture<'_, DomainResult<Vec<ContentReference>>> {
        // Own the filter so the future is `'static` over `&self` and not
        // borrowed from the input slice.
        let target_hex = target.as_ref().to_owned();
        let kind_filter = kind_filter.map(str::to_owned);
        Box::pin(async move {
            tracing::debug!(
                entity = "ContentReference",
                %repo,
                target_content_hash = %target_hex,
                kind_filter = ?kind_filter,
                "find_by_target"
            );
            // Two forms to keep the query planner honest:
            //   - unfiltered: no predicate on kind (returns every row
            //     for the target regardless of kind).
            //   - filtered: strict equality on the indexed kind column
            //     (the OCI Referrers API passes Some("oci_subject")).
            let rows: Vec<ContentReferenceRow> = match kind_filter.as_deref() {
                None => {
                    let sql = format!(
                        r#"SELECT {SELECT_COLS}
                             FROM content_references
                            WHERE repository_id = $1
                              AND target_content_hash = $2
                            ORDER BY recorded_at ASC, source_artifact_id ASC"#
                    );
                    sqlx::query_as(&sql)
                        .bind(repo)
                        .bind(&target_hex)
                        .fetch_all(&self.pool)
                        .await
                }
                Some(kind) => {
                    let sql = format!(
                        r#"SELECT {SELECT_COLS}
                             FROM content_references
                            WHERE repository_id = $1
                              AND target_content_hash = $2
                              AND kind = $3
                            ORDER BY recorded_at ASC, source_artifact_id ASC"#
                    );
                    sqlx::query_as(&sql)
                        .bind(repo)
                        .bind(&target_hex)
                        .bind(kind)
                        .fetch_all(&self.pool)
                        .await
                }
            }
            .map_err(|e| map_sqlx_error(&e, "ContentReference", &format!("{repo}/{target_hex}")))?;
            rows.into_iter().map(row_to_reference).collect()
        })
    }

    fn delete_by_source(&self, source: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "ContentReference",
                %source,
                "delete_by_source"
            );
            // Idempotent — a missing row is not an error. The cascade
            // on `source_artifact_id → artifacts(id) ON DELETE CASCADE`
            // means the row may already have been swept by the time
            // this explicit call runs.
            sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
                .bind(source)
                .execute(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ContentReference", &source.to_string()))?;
            Ok(())
        })
    }

    fn find_by_source_and_kind(
        &self,
        repo: Uuid,
        source: Uuid,
        kind: &str,
    ) -> BoxFuture<'_, DomainResult<Option<ContentReference>>> {
        // Own the kind so the future is `'static` over `&self` and not
        // borrowed from the input slice — same pattern as `find_by_target`.
        let kind = kind.to_owned();
        Box::pin(async move {
            tracing::debug!(
                entity = "ContentReference",
                %repo,
                %source,
                kind = %kind,
                "find_by_source_and_kind"
            );
            // Direct PK lookup — `(repository_id, source_artifact_id,
            // kind)` is the unique key per the migration's PRIMARY KEY.
            let sql = format!(
                r#"SELECT {SELECT_COLS}
                     FROM content_references
                    WHERE repository_id = $1
                      AND source_artifact_id = $2
                      AND kind = $3"#
            );
            let row: Option<ContentReferenceRow> = sqlx::query_as(&sql)
                .bind(repo)
                .bind(source)
                .bind(&kind)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "ContentReference", &format!("{repo}/{source}/{kind}"))
                })?;
            row.map(row_to_reference).transpose()
        })
    }

    fn find_by_sources_and_kind(
        &self,
        repo: Uuid,
        sources: &[Uuid],
        kind: &str,
    ) -> BoxFuture<'_, DomainResult<std::collections::HashMap<Uuid, ContentReference>>> {
        // Own everything so the future is `'static` over `&self` and not
        // borrowed from the input slice.
        let sources_owned: Vec<Uuid> = sources.to_vec();
        let kind = kind.to_owned();
        Box::pin(async move {
            // ONE SQL statement, not N round-trips.
            // Empty input → skip the query entirely (a `WHERE id =
            // ANY(ARRAY[]::uuid[])` would also succeed but pays one
            // pool round-trip we don't owe).
            if sources_owned.is_empty() {
                return Ok(std::collections::HashMap::new());
            }
            tracing::debug!(
                entity = "ContentReference",
                %repo,
                source_count = sources_owned.len(),
                kind = %kind,
                "find_by_sources_and_kind"
            );
            // `ANY($1)` over a UUID[] parameter is the canonical
            // batched-PK form. The query planner uses the composite
            // PRIMARY KEY on `(repository_id, source_artifact_id, kind)`
            // for the index probe.
            let sql = format!(
                r#"SELECT {SELECT_COLS}
                     FROM content_references
                    WHERE repository_id = $1
                      AND source_artifact_id = ANY($2)
                      AND kind = $3"#
            );
            let rows: Vec<ContentReferenceRow> = sqlx::query_as(&sql)
                .bind(repo)
                .bind(&sources_owned)
                .bind(&kind)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(
                        &e,
                        "ContentReference",
                        &format!("{repo}/[{} sources]/{kind}", sources_owned.len()),
                    )
                })?;
            let mut out = std::collections::HashMap::with_capacity(rows.len());
            for row in rows {
                let source_id = row.source_artifact_id;
                let reference = row_to_reference(row)?;
                out.insert(source_id, reference);
            }
            Ok(out)
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    const VALID_SHA256_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const VALID_SHA256_B: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    const VALID_SHA256_C: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    // -- Compile-time port-impl assertions ------------------------------

    /// Compile-time proof the adapter implements the port. Runtime
    /// invocation is covered by the DB-gated integration tests below.
    #[tokio::test]
    async fn pg_content_reference_repo_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgContentReferenceRepo::new(pool);
    }

    #[test]
    fn adapter_implements_port() {
        fn _assert_port<T: ContentReferenceIndex>() {}
        _assert_port::<PgContentReferenceRepo>();
    }

    // -- row_to_reference -----------------------------------------------

    #[test]
    fn row_to_reference_preserves_fields() {
        let repo = Uuid::new_v4();
        let source = Uuid::new_v4();
        let now = Utc::now();
        let metadata = serde_json::json!({
            "artifact_type": "application/vnd.dev.cosign.simplesigning.v1+json",
            "media_type": "application/vnd.oci.image.manifest.v1+json",
        });
        let row = ContentReferenceRow {
            source_artifact_id: source,
            target_content_hash: VALID_SHA256_A.into(),
            kind: "oci_subject".into(),
            metadata: metadata.clone(),
            repository_id: repo,
            recorded_at: now,
        };
        let r = row_to_reference(row).unwrap();
        assert_eq!(r.repository_id, repo);
        assert_eq!(r.source_artifact_id, source);
        assert_eq!(r.target_content_hash.as_ref(), VALID_SHA256_A);
        assert_eq!(r.kind, "oci_subject");
        assert_eq!(r.metadata, metadata);
        assert_eq!(r.recorded_at, now);
    }

    /// The `wheel_metadata` kind (PEP 658 wheel METADATA blob, linked to
    /// its parent wheel artifact) survives the row → domain conversion
    /// seam exactly like the prior kinds.
    #[test]
    fn row_to_reference_preserves_wheel_metadata_kind() {
        let repo = Uuid::new_v4();
        let source = Uuid::new_v4();
        let now = Utc::now();
        let metadata = serde_json::Value::Null;
        let row = ContentReferenceRow {
            source_artifact_id: source,
            target_content_hash: VALID_SHA256_A.into(),
            kind: "wheel_metadata".into(),
            metadata: metadata.clone(),
            repository_id: repo,
            recorded_at: now,
        };
        let r = row_to_reference(row).unwrap();
        assert_eq!(r.repository_id, repo);
        assert_eq!(r.source_artifact_id, source);
        assert_eq!(r.target_content_hash.as_ref(), VALID_SHA256_A);
        assert_eq!(r.kind, "wheel_metadata");
        assert_eq!(r.metadata, metadata);
        assert_eq!(r.recorded_at, now);
    }

    #[test]
    fn row_to_reference_rejects_corrupt_hash() {
        let row = ContentReferenceRow {
            source_artifact_id: Uuid::nil(),
            target_content_hash: "not-a-sha256".into(),
            kind: "oci_subject".into(),
            metadata: serde_json::Value::Null,
            repository_id: Uuid::nil(),
            recorded_at: Utc::now(),
        };
        let err = row_to_reference(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)), "got: {err}");
        assert!(err.to_string().contains("corrupt target_content_hash"));
    }

    // -------------------------------------------------------------------
    // DB-backed integration tests. Skipped (noisy "pass") when
    // `DATABASE_URL` is unset — mirrors the conventions in
    // `ref_registry_repo.rs` / `event_store.rs`.
    //
    // When DATABASE_URL is set the harness:
    //   1. connects with a fresh pool,
    //   2. runs all pending migrations (idempotent),
    //   3. seeds throwaway repository + artifact rows,
    //   4. runs one assertion,
    //   5. cleans up with `ON DELETE CASCADE` on the repo row.
    //
    // Each test uses fresh UUIDs, so concurrent test invocations do
    // not collide.
    // -------------------------------------------------------------------

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

    /// Create a disposable repository row and return its id. Rows we
    /// attach to it cascade away on repo delete.
    async fn seed_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("it-content-ref-{}", id.simple());
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
        .expect("seed repo insert");
        id
    }

    /// Seed an `artifacts` row so we have a valid FK for
    /// `content_references.source_artifact_id`.
    async fn seed_artifact(pool: &PgPool, repo: Uuid, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key
               ) VALUES (
                   $1, $2, $3, $3, '1.0.0', $4,
                   0,
                   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                   'application/octet-stream', $4
               )"#,
        )
        .bind(id)
        .bind(repo)
        .bind(name)
        .bind(format!("artifacts/{name}"))
        .execute(pool)
        .await
        .expect("seed artifact insert");
        id
    }

    async fn cleanup_repo(pool: &PgPool, repo: Uuid) {
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(pool)
            .await;
    }

    fn make_reference(
        repo: Uuid,
        source: Uuid,
        target_hex: &str,
        kind: &str,
        metadata: serde_json::Value,
    ) -> ContentReference {
        ContentReference {
            source_artifact_id: source,
            target_content_hash: target_hex
                .parse()
                .expect("valid sha-256 hex in test fixture"),
            kind: kind.into(),
            metadata,
            repository_id: repo,
            // `TIMESTAMPTZ` stores microseconds — round-tripping a
            // `Utc::now()` that carries nanos would make an eq assert
            // flaky. Truncating via `with_timezone` is the house style.
            recorded_at: Utc::now().with_timezone(&Utc),
        }
    }

    /// Insert → `find_by_target` round-trip preserves the metadata
    /// JSONB exactly. This is the key new contract introduced by the
    /// schema evolution.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn insert_then_find_round_trips_metadata_jsonb() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let source = seed_artifact(&pool, repo, "manifest-jsonb-roundtrip").await;
        let adapter = PgContentReferenceRepo::new(pool.clone());

        let metadata = serde_json::json!({
            "artifact_type": "application/vnd.cncf.sbom",
            "media_type": "application/vnd.oci.image.manifest.v1+json",
        });
        let target: ContentHash = VALID_SHA256_A.parse().unwrap();
        let reference = make_reference(
            repo,
            source,
            VALID_SHA256_A,
            "oci_subject",
            metadata.clone(),
        );
        adapter
            .insert(reference)
            .await
            .expect("insert should succeed");

        let found = adapter
            .find_by_target(repo, &target, Some("oci_subject"))
            .await
            .expect("find_by_target");
        assert_eq!(found.len(), 1);
        let got = &found[0];
        assert_eq!(got.source_artifact_id, source);
        assert_eq!(got.target_content_hash, target);
        assert_eq!(got.kind, "oci_subject");
        assert_eq!(
            got.metadata, metadata,
            "JSONB metadata must round-trip exactly"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// `kind` predicate narrows results — only rows with the matching
    /// `kind` come back; rows with a different kind are excluded.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_target_kind_filter_narrows() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgContentReferenceRepo::new(pool.clone());

        let target: ContentHash = VALID_SHA256_B.parse().unwrap();

        let s_oci = seed_artifact(&pool, repo, "src-oci").await;
        let s_other = seed_artifact(&pool, repo, "src-other").await;

        adapter
            .insert(make_reference(
                repo,
                s_oci,
                VALID_SHA256_B,
                "oci_subject",
                serde_json::json!({"artifact_type": "application/vnd.x"}),
            ))
            .await
            .unwrap();
        adapter
            .insert(make_reference(
                repo,
                s_other,
                VALID_SHA256_B,
                "sbom_attachment",
                serde_json::json!({}),
            ))
            .await
            .unwrap();

        // Filter = oci_subject → exactly the OCI row.
        let only_oci = adapter
            .find_by_target(repo, &target, Some("oci_subject"))
            .await
            .unwrap();
        assert_eq!(only_oci.len(), 1);
        assert_eq!(only_oci[0].source_artifact_id, s_oci);

        // Filter = None → both rows.
        let all = adapter.find_by_target(repo, &target, None).await.unwrap();
        assert_eq!(all.len(), 2);

        // Unknown kind → empty.
        let nobody = adapter
            .find_by_target(repo, &target, Some("no_such_kind"))
            .await
            .unwrap();
        assert!(nobody.is_empty());

        cleanup_repo(&pool, repo).await;
    }

    /// `delete_by_source` removes the row; a follow-up
    /// `find_by_target` returns empty.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn delete_by_source_removes_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgContentReferenceRepo::new(pool.clone());

        let source = seed_artifact(&pool, repo, "src-delete").await;
        let target: ContentHash = VALID_SHA256_C.parse().unwrap();
        adapter
            .insert(make_reference(
                repo,
                source,
                VALID_SHA256_C,
                "oci_subject",
                serde_json::json!({}),
            ))
            .await
            .unwrap();

        // Pre-delete sanity.
        let pre = adapter.find_by_target(repo, &target, None).await.unwrap();
        assert_eq!(pre.len(), 1);

        adapter.delete_by_source(source).await.unwrap();

        // Post-delete — empty.
        let post = adapter.find_by_target(repo, &target, None).await.unwrap();
        assert!(post.is_empty(), "row must be gone after delete_by_source");

        // Second delete of the same source is idempotent.
        adapter.delete_by_source(source).await.unwrap();

        // Delete of a never-recorded source is also idempotent.
        adapter.delete_by_source(Uuid::new_v4()).await.unwrap();

        cleanup_repo(&pool, repo).await;
    }

    /// Insert with the same (repo, source) PK is an upsert — fields
    /// are refreshed, not a 409. This is the contract idempotent
    /// manifest-PUT retry relies on.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn insert_upserts_on_primary_key() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgContentReferenceRepo::new(pool.clone());

        let source = seed_artifact(&pool, repo, "src-upsert").await;
        adapter
            .insert(make_reference(
                repo,
                source,
                VALID_SHA256_A,
                "oci_subject",
                serde_json::json!({"artifact_type": "application/vnd.first"}),
            ))
            .await
            .expect("first insert");

        // Re-insert under the same PK with a different target and
        // different metadata — should refresh, not fail.
        let new_target: ContentHash = VALID_SHA256_B.parse().unwrap();
        adapter
            .insert(ContentReference {
                source_artifact_id: source,
                target_content_hash: new_target.clone(),
                kind: "oci_subject".into(),
                metadata: serde_json::json!({"artifact_type": "application/vnd.second"}),
                repository_id: repo,
                recorded_at: Utc::now(),
            })
            .await
            .expect("second insert (upsert) must succeed");

        // The new target wins.
        let by_new = adapter
            .find_by_target(repo, &new_target, None)
            .await
            .unwrap();
        assert_eq!(by_new.len(), 1);
        assert_eq!(by_new[0].source_artifact_id, source);
        assert_eq!(
            by_new[0].metadata,
            serde_json::json!({"artifact_type": "application/vnd.second"}),
        );

        // The old target is gone — the upsert replaced, not appended.
        let old_target: ContentHash = VALID_SHA256_A.parse().unwrap();
        let by_old = adapter
            .find_by_target(repo, &old_target, None)
            .await
            .unwrap();
        assert!(
            by_old.is_empty(),
            "upsert must replace the target, not leave the old row",
        );

        cleanup_repo(&pool, repo).await;
    }

    /// Two rows under the SAME `(repository_id, source_artifact_id)`
    /// but DIFFERENT `kind` values must coexist. The PK shape
    /// `(repository_id, source_artifact_id, kind)` makes that an
    /// additive insert, not an upsert.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn insert_distinct_kinds_coexist() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgContentReferenceRepo::new(pool.clone());

        let source = seed_artifact(&pool, repo, "src-distinct-kinds").await;

        // Same source, two kinds, two different targets.
        adapter
            .insert(make_reference(
                repo,
                source,
                VALID_SHA256_A,
                "oci_subject",
                serde_json::json!({}),
            ))
            .await
            .expect("oci_subject insert");
        adapter
            .insert(make_reference(
                repo,
                source,
                VALID_SHA256_B,
                "primary_content",
                serde_json::json!({}),
            ))
            .await
            .expect("primary_content insert");

        // Direct count via SQL — finer-grained than `find_by_target`,
        // which is keyed by target hash. We want "rows for this source"
        // regardless of target.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_references WHERE source_artifact_id = $1",
        )
        .bind(source)
        .fetch_one(&pool)
        .await
        .expect("COUNT");
        assert_eq!(
            count, 2,
            "two rows must coexist for the same source under different kinds",
        );

        cleanup_repo(&pool, repo).await;
    }

    /// `delete_by_source` sweeps EVERY row for the source, regardless
    /// of kind. Verifies the per-source delete acts like a hard sweep.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn delete_by_source_sweeps_all_kinds() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgContentReferenceRepo::new(pool.clone());

        let source = seed_artifact(&pool, repo, "src-sweep").await;

        // Three rows, three different kinds.
        adapter
            .insert(make_reference(
                repo,
                source,
                VALID_SHA256_A,
                "oci_subject",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        adapter
            .insert(make_reference(
                repo,
                source,
                VALID_SHA256_B,
                "primary_content",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        adapter
            .insert(make_reference(
                repo,
                source,
                VALID_SHA256_C,
                "metadata_blob",
                serde_json::json!({}),
            ))
            .await
            .unwrap();

        let pre: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_references WHERE source_artifact_id = $1",
        )
        .bind(source)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(pre, 3);

        adapter.delete_by_source(source).await.unwrap();

        let post: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_references WHERE source_artifact_id = $1",
        )
        .bind(source)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            post, 0,
            "delete_by_source must sweep every row for the source regardless of kind",
        );

        cleanup_repo(&pool, repo).await;
    }

    /// Kind-agnostic count over `target_content_hash` is the basis for
    /// the GC-eligibility query. A target referenced by both an
    /// `oci_subject` row and a `primary_content` row must show count = 2.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_target_kind_agnostic_count() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgContentReferenceRepo::new(pool.clone());

        let target: ContentHash = VALID_SHA256_A.parse().unwrap();

        let s_oci = seed_artifact(&pool, repo, "src-target-oci").await;
        let s_primary = seed_artifact(&pool, repo, "src-target-primary").await;

        adapter
            .insert(make_reference(
                repo,
                s_oci,
                VALID_SHA256_A,
                "oci_subject",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        adapter
            .insert(make_reference(
                repo,
                s_primary,
                VALID_SHA256_A,
                "primary_content",
                serde_json::json!({}),
            ))
            .await
            .unwrap();

        // Direct kind-agnostic SQL count — mirrors the shape of the
        // Phase B GC-eligibility query.
        let count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)
                 FROM content_references
                WHERE repository_id = $1
                  AND target_content_hash = $2"#,
        )
        .bind(repo)
        .bind(target.as_ref())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            count, 2,
            "kind-agnostic COUNT(*) over a shared target must include every kind"
        );

        cleanup_repo(&pool, repo).await;
    }
}
