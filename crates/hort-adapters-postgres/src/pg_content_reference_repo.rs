//! PostgreSQL adapter for [`ContentReferenceIndex`].
//!
//! Implements the content-reference projection. One row per
//! `(repository_id, source_artifact_id, target_content_hash, kind)`. The
//! same source artifact may carry rows of different `kind` simultaneously
//! — e.g. an OCI manifest carries an `oci_subject` row (its
//! `subject.digest`) AND a `primary_content` row (its own SHA-256) — and,
//! since the PK includes `target_content_hash`, it may also carry
//! **multiple targets under one `kind`** (an OCI image index carries one
//! `oci_index_member` row per child manifest hash). Lookup by target
//! content hash is a direct btree hit via `idx_content_references_target`.
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
//! - `"oci_index_member"` — OCI image-index / manifest-list membership.
//!   Written one-per-child on an index PUT (`source =` the index,
//!   `target =` each child manifest's own hash). The first consumer of
//!   the widened PK — N rows share `(source, kind)`, each with a
//!   distinct `target_content_hash`.
//!
//! # Upsert semantics
//!
//! `insert` runs
//!
//! ```sql
//! INSERT INTO content_references (...)
//! VALUES (...)
//! ON CONFLICT (repository_id, source_artifact_id, target_content_hash, kind)
//! DO UPDATE SET
//!     metadata    = EXCLUDED.metadata,
//!     recorded_at = EXCLUDED.recorded_at
//! ```
//!
//! Idempotent re-ingest of the same `(source, target, kind)` (the OCI
//! manifest-PUT retry) refreshes the row rather than tripping a
//! unique-constraint violation. `target_content_hash` is part of the
//! conflict key, so it cannot change on a conflict — the `DO UPDATE`
//! refreshes only `metadata` / `recorded_at`. Inserting the same source
//! under a *different* kind OR a different target adds a sibling row —
//! the refcount design and the OCI index's N-children membership both
//! require this.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::types::ContentHash;

use crate::contention::{contention_backoff, with_contention_retry, CONTENTION_RETRY_ATTEMPTS};
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
            // Retried on a contention abort. Sibling manifests of one push
            // share targets by construction — every attestation manifest in a
            // buildkit image index references the same empty-config blob — so
            // their edge upserts contend on a single row whenever the push is
            // concurrent, which for a multi-architecture client it always is.
            // The upsert is one self-contained statement, so re-running it is
            // re-running the whole unit of work; and it is idempotent by the
            // `ON CONFLICT DO UPDATE` above, so a re-run cannot double-write
            // even in the case where the abort was reported after the row
            // landed. A genuine `Conflict` is not retried here (see
            // `crate::contention`), which is what keeps that idempotence
            // intact rather than papering over it.
            with_contention_retry(
                "content-reference upsert",
                CONTENTION_RETRY_ATTEMPTS,
                contention_backoff,
                || {
                    let target_hex = target_hex.clone();
                    let reference = &reference;
                    async move {
                        sqlx::query(
                            r#"INSERT INTO content_references (
                       source_artifact_id, target_content_hash, kind, metadata,
                       repository_id, recorded_at
                   ) VALUES ($1, $2, $3, $4, $5, $6)
                   ON CONFLICT (repository_id, source_artifact_id, target_content_hash, kind)
                   DO UPDATE SET
                       metadata    = EXCLUDED.metadata,
                       recorded_at = EXCLUDED.recorded_at"#,
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
                    }
                },
            )
            .await?;
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
                    sqlx::query_as(sqlx::AssertSqlSafe(sql))
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
                    sqlx::query_as(sqlx::AssertSqlSafe(sql))
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
            // Single-target-kind lookup. The PK is now
            // `(repository_id, source_artifact_id, target_content_hash,
            // kind)`, so `(repo, source, kind)` is unique only for the
            // single-target kinds this method serves (`wheel_metadata`,
            // `metadata_blob`, `oci_subject` — each has exactly one
            // target per source). The N-target `oci_index_member` kind is
            // never read through here (it is read cross-source via
            // `find_by_target` and counted by GC), so `fetch_optional`'s
            // at-most-one contract holds for every actual caller.
            let sql = format!(
                r#"SELECT {SELECT_COLS}
                     FROM content_references
                    WHERE repository_id = $1
                      AND source_artifact_id = $2
                      AND kind = $3"#
            );
            let row: Option<ContentReferenceRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
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
            // batched form. The query planner uses the composite PRIMARY
            // KEY on `(repository_id, source_artifact_id,
            // target_content_hash, kind)` — its leading columns cover
            // `(repository_id, source_artifact_id)` — for the index
            // probe. Callers pass single-target kinds only, so each
            // source yields at most one row and the result folds cleanly
            // into a `source_id → reference` map.
            let sql = format!(
                r#"SELECT {SELECT_COLS}
                     FROM content_references
                    WHERE repository_id = $1
                      AND source_artifact_id = ANY($2)
                      AND kind = $3"#
            );
            let rows: Vec<ContentReferenceRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
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

    /// Idempotent re-insert of the SAME `(source, target, kind)` refreshes
    /// the row (metadata / recorded_at) rather than tripping a 409 — the
    /// contract the idempotent manifest-PUT retry relies on. With the
    /// widened PK `(repository_id, source_artifact_id,
    /// target_content_hash, kind)`, "same PK" now includes the target, so
    /// this is the exact key an identical re-push presents.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn insert_upserts_on_primary_key() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgContentReferenceRepo::new(pool.clone());

        let source = seed_artifact(&pool, repo, "src-upsert").await;
        let target: ContentHash = VALID_SHA256_A.parse().unwrap();
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

        // Re-insert under the SAME (source, target, kind) with different
        // metadata — must refresh the row, not fail and not append.
        adapter
            .insert(ContentReference {
                source_artifact_id: source,
                target_content_hash: target.clone(),
                kind: "oci_subject".into(),
                metadata: serde_json::json!({"artifact_type": "application/vnd.second"}),
                repository_id: repo,
                recorded_at: Utc::now(),
            })
            .await
            .expect("second insert (upsert) must succeed");

        // Exactly one row, with the refreshed metadata.
        let rows = adapter.find_by_target(repo, &target, None).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "same (source, target, kind) upserts in place"
        );
        assert_eq!(rows[0].source_artifact_id, source);
        assert_eq!(
            rows[0].metadata,
            serde_json::json!({"artifact_type": "application/vnd.second"}),
            "metadata is refreshed on the idempotent re-push",
        );

        cleanup_repo(&pool, repo).await;
    }

    // -------------------------------------------------------------------
    // Write contention.
    //
    // Concurrent hosted manifest PUTs contend on `content_references` by
    // construction: sibling manifests of one push share targets (every
    // attestation manifest in a buildkit image index references the same
    // empty-config blob), so their edge upserts land on one row.
    //
    // The two classifier tests below deliberately provoke a REAL Postgres
    // abort rather than hand-building an error value. The whole change rests
    // on `40001` / `40P01` being the codes this engine actually reports for
    // these two conditions; a test that asserted a constant against itself
    // would hold even if the codes were wrong, which is the one failure mode
    // worth ruling out.
    // -------------------------------------------------------------------

    /// Update a seeded row inside `tx`, returning the raw `sqlx` error so
    /// the caller can inspect its SQLSTATE.
    async fn touch_row(
        tx: &mut sqlx::PgConnection,
        repo: Uuid,
        source: Uuid,
        target_hex: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE content_references SET recorded_at = now() \
             WHERE repository_id = $1 AND source_artifact_id = $2 \
               AND target_content_hash = $3 AND kind = 'oci_config'",
        )
        .bind(repo)
        .bind(source)
        .bind(target_hex)
        .execute(&mut *tx)
        .await
        .map(|_| ())
    }

    /// A genuine Postgres **deadlock** maps to [`DomainError::Contended`],
    /// not [`DomainError::Invariant`].
    ///
    /// Two transactions take the same two row locks in opposite order, so
    /// Postgres has to break the cycle by aborting one of them. The victim's
    /// transaction is rolled back whole — nothing it wrote survives — which
    /// is exactly why re-running it is safe, and why classifying it as an
    /// invariant breach (and answering 500) misdescribes it.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_real_deadlock_classifies_as_contended() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgContentReferenceRepo::new(pool.clone());

        let source_a = seed_artifact(&pool, repo, "deadlock-a").await;
        let source_b = seed_artifact(&pool, repo, "deadlock-b").await;
        for (source, target) in [(source_a, VALID_SHA256_A), (source_b, VALID_SHA256_B)] {
            adapter
                .insert(make_reference(
                    repo,
                    source,
                    target,
                    "oci_config",
                    serde_json::json!({}),
                ))
                .await
                .expect("seed row");
        }

        // Both transactions must hold their first lock before either asks
        // for the second — otherwise one simply finishes and there is no
        // cycle to detect.
        let gate = std::sync::Arc::new(tokio::sync::Barrier::new(2));

        let run_one = |first: (Uuid, &'static str), second: (Uuid, &'static str)| {
            let pool = pool.clone();
            let gate = gate.clone();
            async move {
                let mut tx = pool.begin().await.expect("begin");
                // Shorten the detector's wait where the role is allowed to;
                // the cluster default (1s) is a correct fallback, just
                // slower, so a refusal here is not a failure.
                let _ = sqlx::query("SET LOCAL deadlock_timeout = '150ms'")
                    .execute(&mut *tx)
                    .await;
                touch_row(&mut tx, repo, first.0, first.1)
                    .await
                    .expect("first lock");
                gate.wait().await;
                let outcome = touch_row(&mut tx, repo, second.0, second.1).await;
                // Explicit rollback for the survivor; the victim's
                // transaction is already aborted and this is a no-op.
                let _ = tx.rollback().await;
                outcome
            }
        };

        let (first, second) = tokio::join!(
            run_one((source_a, VALID_SHA256_A), (source_b, VALID_SHA256_B)),
            run_one((source_b, VALID_SHA256_B), (source_a, VALID_SHA256_A)),
        );

        let victim = match (first, second) {
            (Err(e), Ok(())) | (Ok(()), Err(e)) => e,
            (Ok(()), Ok(())) => {
                cleanup_repo(&pool, repo).await;
                panic!(
                    "no deadlock was produced — the two transactions did not \
                     actually contend, so this test proves nothing"
                );
            }
            (Err(a), Err(b)) => {
                cleanup_repo(&pool, repo).await;
                panic!("both transactions failed, expected exactly one victim: {a} / {b}");
            }
        };

        let code = victim
            .as_database_error()
            .and_then(|db| db.code().map(std::borrow::Cow::into_owned))
            .unwrap_or_default();
        assert_eq!(
            code, "40P01",
            "expected Postgres to report deadlock_detected; got {code:?} ({victim})"
        );
        assert!(
            crate::contention::is_contention(&victim),
            "the adapter must recognise a real deadlock as transient contention"
        );
        assert!(
            matches!(
                map_sqlx_error(&victim, "ContentReference", "test"),
                DomainError::Contended(_)
            ),
            "a deadlock must map to Contended — mapping it to Invariant is what \
             turned concurrent manifest PUTs into intermittent 500s"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// A genuine Postgres **serialization failure** maps to
    /// [`DomainError::Contended`] too — the other half of the pair, and the
    /// one an isolation level above READ COMMITTED produces.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_real_serialization_failure_classifies_as_contended() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgContentReferenceRepo::new(pool.clone());
        let source = seed_artifact(&pool, repo, "serialization-victim").await;
        adapter
            .insert(make_reference(
                repo,
                source,
                VALID_SHA256_A,
                "oci_config",
                serde_json::json!({}),
            ))
            .await
            .expect("seed row");

        // The reader takes its snapshot first, the writer commits under it,
        // and the reader's own write then cannot be serialized against a row
        // that moved beneath its snapshot.
        let mut reader = pool.begin().await.expect("begin reader");
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *reader)
            .await
            .expect("set isolation");
        sqlx::query("SELECT 1 FROM content_references WHERE repository_id = $1")
            .bind(repo)
            .fetch_all(&mut *reader)
            .await
            .expect("establish snapshot");

        let mut writer = pool.begin().await.expect("begin writer");
        touch_row(&mut writer, repo, source, VALID_SHA256_A)
            .await
            .expect("writer update");
        writer.commit().await.expect("writer commit");

        let outcome = touch_row(&mut reader, repo, source, VALID_SHA256_A).await;
        let _ = reader.rollback().await;

        let Err(err) = outcome else {
            cleanup_repo(&pool, repo).await;
            panic!("expected a serialization failure, the update succeeded");
        };
        let code = err
            .as_database_error()
            .and_then(|db| db.code().map(std::borrow::Cow::into_owned))
            .unwrap_or_default();
        assert_eq!(
            code, "40001",
            "expected Postgres to report serialization_failure; got {code:?} ({err})"
        );
        assert!(
            matches!(
                map_sqlx_error(&err, "ContentReference", "test"),
                DomainError::Contended(_)
            ),
            "a serialization failure must map to Contended, not Invariant"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// Concurrent edge upserts contending on **one shared target** all
    /// succeed, and every row lands.
    ///
    /// This is the incident's shape: several manifests of a single
    /// multi-architecture push write their `oci_config` edge at the same
    /// time, and because the attestation manifests all reference the OCI
    /// empty-config blob, those writes converge on one target hash. The
    /// claim asserted here is the one that matters to a client: every
    /// concurrent writer completes and no write is lost — not "one of them
    /// errors and the caller is expected to work it out".
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn concurrent_upserts_on_a_shared_target_all_succeed() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = std::sync::Arc::new(PgContentReferenceRepo::new(pool.clone()));

        // Eight distinct manifests, one shared config target — plus a
        // second writer per source presenting the IDENTICAL primary key, so
        // the run covers both same-target-different-row contention and the
        // pure idempotent-upsert collision on one row.
        const WRITERS: usize = 8;
        let shared_target = VALID_SHA256_C;
        let mut sources = Vec::with_capacity(WRITERS);
        for i in 0..WRITERS {
            sources.push(seed_artifact(&pool, repo, &format!("concurrent-src-{i}")).await);
        }

        let mut handles = Vec::new();
        for (i, source) in sources.iter().copied().enumerate() {
            for pass in 0..2u32 {
                let adapter = adapter.clone();
                handles.push(tokio::spawn(async move {
                    adapter
                        .insert(make_reference(
                            repo,
                            source,
                            shared_target,
                            "oci_config",
                            serde_json::json!({"writer": i, "pass": pass}),
                        ))
                        .await
                }));
            }
        }

        let mut failures = Vec::new();
        for handle in handles {
            match handle.await.expect("writer task did not panic") {
                Ok(()) => {}
                Err(e) => failures.push(e),
            }
        }
        assert!(
            failures.is_empty(),
            "every concurrent edge upsert must succeed; {} failed: {failures:?}",
            failures.len()
        );

        let rows = adapter
            .find_by_target(repo, &shared_target.parse().unwrap(), Some("oci_config"))
            .await
            .expect("read back the shared target");
        assert_eq!(
            rows.len(),
            WRITERS,
            "one row per source survives the contention — the second pass upserts \
             its own row rather than displacing a sibling's"
        );
        let distinct: std::collections::HashSet<Uuid> =
            rows.iter().map(|r| r.source_artifact_id).collect();
        assert_eq!(
            distinct.len(),
            WRITERS,
            "no source's edge was lost to a concurrent writer"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// The widened PK makes a re-insert under the same `(source, kind)`
    /// but a DIFFERENT `target_content_hash` a SIBLING row, not a
    /// replacement — this is the many-to-many the OCI image index needs
    /// (one index carries N `oci_index_member` rows). Under the old narrow
    /// `(repo, source, kind)` PK the second insert would have overwritten
    /// the first; here both coexist.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn insert_same_source_kind_distinct_targets_coexist() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgContentReferenceRepo::new(pool.clone());

        let source = seed_artifact(&pool, repo, "src-multitarget").await;

        // Two members under one (source, kind = "oci_index_member"),
        // distinct only by target hash.
        adapter
            .insert(make_reference(
                repo,
                source,
                VALID_SHA256_A,
                "oci_index_member",
                serde_json::json!({}),
            ))
            .await
            .expect("first member insert");
        adapter
            .insert(make_reference(
                repo,
                source,
                VALID_SHA256_B,
                "oci_index_member",
                serde_json::json!({}),
            ))
            .await
            .expect("second member insert must NOT overwrite the first");

        // Both targets are present and independently resolvable.
        let target_a: ContentHash = VALID_SHA256_A.parse().unwrap();
        let target_b: ContentHash = VALID_SHA256_B.parse().unwrap();
        assert_eq!(
            adapter
                .find_by_target(repo, &target_a, None)
                .await
                .unwrap()
                .len(),
            1,
            "the first target survives the second insert",
        );
        assert_eq!(
            adapter
                .find_by_target(repo, &target_b, None)
                .await
                .unwrap()
                .len(),
            1,
            "the second target is a sibling, not a replacement",
        );

        // Two rows under the one (source, kind).
        let count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM content_references
                WHERE source_artifact_id = $1 AND kind = 'oci_index_member'"#,
        )
        .bind(source)
        .fetch_one(&pool)
        .await
        .expect("COUNT");
        assert_eq!(count, 2, "N targets coexist under one (source, kind)");

        cleanup_repo(&pool, repo).await;
    }

    /// Two rows under the SAME `(repository_id, source_artifact_id)`
    /// but DIFFERENT `kind` values must coexist. The PK shape
    /// `(repository_id, source_artifact_id, target_content_hash, kind)`
    /// makes that an additive insert, not an upsert.
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

    /// The widened PK (migration 013) admits N `oci_index_member` rows
    /// under ONE `(source = index, kind = "oci_index_member")`, one per
    /// child manifest hash — the OCI image-index membership. This is the
    /// contract the old narrow `(repo, source, kind)` PK could not hold
    /// (it collapsed them to the last child). Also proves the GC
    /// alive-keep basis: while the index's member rows are live, the
    /// kind-agnostic COUNT over a child's `target_content_hash` is > 0,
    /// and drops to 0 once `delete_by_source(index)` sweeps them.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn index_writes_n_member_rows_under_one_source_kind() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgContentReferenceRepo::new(pool.clone());

        // The index artifact is the SINGLE source of every member row.
        let index = seed_artifact(&pool, repo, "image-index").await;

        // Three children under one (source = index, kind =
        // "oci_index_member"), distinct only by target hash. Under the
        // old narrow PK this would upsert to one surviving row; under
        // the widened PK all three coexist.
        for child_hex in [VALID_SHA256_A, VALID_SHA256_B, VALID_SHA256_C] {
            adapter
                .insert(make_reference(
                    repo,
                    index,
                    child_hex,
                    "oci_index_member",
                    serde_json::json!({"child_digest": format!("sha256:{child_hex}")}),
                ))
                .await
                .expect("oci_index_member insert");
        }

        // All three member rows persist under the ONE source.
        let member_count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM content_references
                WHERE source_artifact_id = $1 AND kind = 'oci_index_member'"#,
        )
        .bind(index)
        .fetch_one(&pool)
        .await
        .expect("member COUNT");
        assert_eq!(
            member_count, 3,
            "the widened PK admits N members under one (source, kind)"
        );

        // GC alive-keep basis: while a member row is live, the
        // kind-agnostic count over its child target is > 0.
        let child_a: ContentHash = VALID_SHA256_A.parse().unwrap();
        let live: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM content_references
                WHERE target_content_hash = $1"#,
        )
        .bind(child_a.as_ref())
        .fetch_one(&pool)
        .await
        .expect("live COUNT");
        assert!(
            live > 0,
            "a live index keeps each child's CAS blob alive (target-keyed refcount)"
        );

        // Sweeping the index's rows (its DELETE / purge, or FK cascade)
        // frees every child: the target-keyed count drops to 0.
        adapter.delete_by_source(index).await.unwrap();
        let after: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM content_references
                WHERE target_content_hash = $1"#,
        )
        .bind(child_a.as_ref())
        .fetch_one(&pool)
        .await
        .expect("post-sweep COUNT");
        assert_eq!(
            after, 0,
            "once the index's member rows are swept, the child's refcount is 0"
        );

        cleanup_repo(&pool, repo).await;
    }
}
