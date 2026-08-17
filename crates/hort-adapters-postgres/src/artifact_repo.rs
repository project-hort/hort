use chrono::{DateTime, Utc};
use sqlx::postgres::PgArguments;
use sqlx::{AssertSqlSafe, PgPool};
use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::types::{ContentHash, LimitedList, Page, PageRequest, LIMIT_LIST_MAX_ITEMS};

use crate::event_store::PgUnitOfWork;
use crate::mappers::ArtifactRow;
use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`ArtifactRepository`].
pub struct PgArtifactRepository {
    pool: PgPool,
}

impl PgArtifactRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const SELECT_COLS: &str = r#"
    id, repository_id, name, name_as_published, version, path,
    size_bytes, checksum_sha256, checksum_sha1, checksum_md5,
    content_type, storage_key,
    quarantine_status, quarantine_window_start, upstream_published_at,
    uploaded_by, is_deleted,
    created_at, updated_at
"#;

const UPSERT_SQL: &str = r#"
    INSERT INTO artifacts (
        id, repository_id, name, name_as_published, version, path,
        size_bytes, checksum_sha256, checksum_sha1, checksum_md5,
        content_type, storage_key,
        quarantine_status, quarantine_window_start, upstream_published_at,
        uploaded_by, is_deleted,
        created_at, updated_at
    )
    VALUES (
        $1, $2, $3, $4, $5, $6,
        $7, $8, $9, $10,
        $11, $12,
        $13, $14, $15,
        $16, $17,
        $18, $19
    )
    ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        name_as_published = EXCLUDED.name_as_published,
        version = EXCLUDED.version,
        path = EXCLUDED.path,
        size_bytes = EXCLUDED.size_bytes,
        checksum_sha256 = EXCLUDED.checksum_sha256,
        checksum_sha1 = EXCLUDED.checksum_sha1,
        checksum_md5 = EXCLUDED.checksum_md5,
        content_type = EXCLUDED.content_type,
        storage_key = EXCLUDED.storage_key,
        quarantine_status = EXCLUDED.quarantine_status,
        quarantine_window_start = EXCLUDED.quarantine_window_start,
        upstream_published_at = EXCLUDED.upstream_published_at,
        uploaded_by = EXCLUDED.uploaded_by,
        is_deleted = EXCLUDED.is_deleted,
        updated_at = EXCLUDED.updated_at
"#;

/// Bind all artifact fields to an UPSERT query in parameter order.
fn bind_artifact_params<'q>(
    query: sqlx::query::Query<'q, sqlx::Postgres, PgArguments>,
    artifact: &'q Artifact,
    quarantine_str: &'q Option<String>,
    storage_key: &'q str,
) -> sqlx::query::Query<'q, sqlx::Postgres, PgArguments> {
    query
        .bind(artifact.id)
        .bind(artifact.repository_id)
        .bind(&artifact.name)
        .bind(&artifact.name_as_published)
        .bind(&artifact.version)
        .bind(&artifact.path)
        .bind(artifact.size_bytes)
        .bind(artifact.sha256_checksum.as_ref())
        .bind(&artifact.sha1_checksum)
        .bind(&artifact.md5_checksum)
        .bind(&artifact.content_type)
        .bind(storage_key)
        .bind(quarantine_str)
        .bind(artifact.quarantine_window_start)
        .bind(artifact.upstream_published_at)
        .bind(artifact.uploaded_by)
        .bind(artifact.is_deleted)
        .bind(artifact.created_at)
        .bind(artifact.updated_at)
}

impl ArtifactRepository for PgArtifactRepository {
    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Artifact>> {
        Box::pin(async move {
            tracing::debug!(entity = "Artifact", %id, "find_by_id");
            let sql = format!("SELECT {SELECT_COLS} FROM artifacts WHERE id = $1");
            let row: ArtifactRow = sqlx::query_as(AssertSqlSafe(sql))
                .bind(id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", &id.to_string()))?;
            Artifact::try_from(row)
        })
    }

    fn find_by_checksum(
        &self,
        sha256: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
        let sha256 = sha256.as_ref().to_string();
        Box::pin(async move {
            tracing::debug!(entity = "Artifact", sha256 = %sha256, "find_by_checksum");
            let sql =
                format!("SELECT {SELECT_COLS} FROM artifacts WHERE checksum_sha256 = $1 LIMIT 1");
            let row: Option<ArtifactRow> = sqlx::query_as(AssertSqlSafe(sql))
                .bind(&sha256)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", &sha256))?;
            row.map(Artifact::try_from).transpose()
        })
    }

    fn find_by_repo_and_checksum(
        &self,
        repository_id: Uuid,
        sha256: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
        let sha256 = sha256.as_ref().to_string();
        Box::pin(async move {
            tracing::debug!(
                entity = "Artifact",
                %repository_id,
                sha256 = %sha256,
                "find_by_repo_and_checksum"
            );
            let sql = format!(
                "SELECT {SELECT_COLS} FROM artifacts \
                 WHERE repository_id = $1 AND checksum_sha256 = $2 LIMIT 1"
            );
            let row: Option<ArtifactRow> = sqlx::query_as(AssertSqlSafe(sql))
                .bind(repository_id)
                .bind(&sha256)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", &sha256))?;
            row.map(Artifact::try_from).transpose()
        })
    }

    fn first_seen_for_checksum(
        &self,
        sha256: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Option<DateTime<Utc>>>> {
        let sha256 = sha256.as_ref().to_string();
        Box::pin(async move {
            tracing::debug!(entity = "Artifact", sha256 = %sha256, "first_seen_for_checksum");
            // Unscoped by repository AND unfiltered by `is_deleted`, both
            // deliberately: the question is "when did hort first hold
            // these bytes, anywhere", and a soft-delete withdraws a row
            // from service without un-observing the bytes. `MIN` over the
            // `idx_artifacts_checksum` equality range — no new index, no
            // stored projection to keep in step.
            //
            // `fetch_one` (not `fetch_optional`): an aggregate over an
            // empty range still returns exactly one row, carrying SQL
            // NULL, which maps to the `None` the caller reads as
            // "no evidence".
            let (first_seen,): (Option<DateTime<Utc>>,) =
                sqlx::query_as("SELECT MIN(created_at) FROM artifacts WHERE checksum_sha256 = $1")
                    .bind(&sha256)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| map_sqlx_error(&e, "Artifact", &sha256))?;
            Ok(first_seen)
        })
    }

    fn list_by_repository(
        &self,
        repository_id: Uuid,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<Artifact>>> {
        let offset = page.offset as i64;
        let limit = page.limit as i64;
        Box::pin(async move {
            tracing::debug!(entity = "Artifact", %repository_id, "list_by_repository");
            let sql = format!(
                r#"SELECT {SELECT_COLS}
                   FROM artifacts
                   WHERE repository_id = $1
                   ORDER BY name, version
                   OFFSET $2 LIMIT $3"#
            );
            let rows: Vec<ArtifactRow> = sqlx::query_as(AssertSqlSafe(sql))
                .bind(repository_id)
                .bind(offset)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", "list"))?;

            let total: Option<i64> =
                sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                    .bind(repository_id)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| map_sqlx_error(&e, "Artifact", "count"))?;

            let items: Vec<Artifact> = rows
                .into_iter()
                .map(Artifact::try_from)
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Page {
                items,
                total: total.unwrap_or(0) as u64,
            })
        })
    }

    fn delete(&self, id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(entity = "Artifact", %id, "delete");
            let result = sqlx::query("DELETE FROM artifacts WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", &id.to_string()))?;

            if result.rows_affected() == 0 {
                return Err(DomainError::NotFound {
                    entity: "Artifact",
                    id: id.to_string(),
                });
            }
            Ok(())
        })
    }

    fn find_by_path(
        &self,
        repository_id: Uuid,
        path: &str,
    ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
        let path = path.to_owned();
        Box::pin(async move {
            tracing::debug!(entity = "Artifact", %repository_id, %path, "find_by_path");
            let sql = format!(
                "SELECT {SELECT_COLS} FROM artifacts WHERE repository_id = $1 AND path = $2"
            );
            let row: Option<ArtifactRow> = sqlx::query_as(AssertSqlSafe(sql))
                .bind(repository_id)
                .bind(&path)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", &path))?;
            row.map(Artifact::try_from).transpose()
        })
    }

    fn list_distinct_names(
        &self,
        repository_id: Uuid,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<String>>> {
        let offset = page.offset as i64;
        let limit = page.limit as i64;
        Box::pin(async move {
            tracing::debug!(entity = "Artifact", %repository_id, "list_distinct_names");
            // Paginated. Without OFFSET/LIMIT a repo with N distinct
            // names loaded N strings into memory unconditionally; the
            // use-case layer now iterates pages up to the
            // `LIMIT_LIST_MAX_ITEMS` cap.
            let names: Vec<String> = sqlx::query_scalar(
                "SELECT DISTINCT name FROM artifacts \
                 WHERE repository_id = $1 AND is_deleted = false \
                 ORDER BY name \
                 OFFSET $2 LIMIT $3",
            )
            .bind(repository_id)
            .bind(offset)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Artifact", "distinct_names"))?;

            // Total is materialised by a separate `COUNT(DISTINCT …)`. The
            // use-case layer's iterate-until-exhaustion loop only consults
            // `items.len() < page.limit` to detect the last page, but
            // exposing the total is consistent with `list_by_repository`.
            let total: Option<i64> = sqlx::query_scalar(
                "SELECT COUNT(DISTINCT name) FROM artifacts \
                 WHERE repository_id = $1 AND is_deleted = false",
            )
            .bind(repository_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Artifact", "distinct_names_count"))?;

            Ok(Page {
                items: names,
                total: total.unwrap_or(0) as u64,
            })
        })
    }

    fn find_by_name_in_repo(
        &self,
        repository_id: Uuid,
        normalized_name: &str,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<Artifact>>> {
        let name = normalized_name.to_owned();
        let offset = page.offset as i64;
        let limit = page.limit as i64;
        Box::pin(async move {
            tracing::debug!(entity = "Artifact", %repository_id, %name, "find_by_name_in_repo");
            // Paginated.
            let sql = format!(
                "SELECT {SELECT_COLS} FROM artifacts \
                 WHERE repository_id = $1 AND name = $2 \
                 ORDER BY version \
                 OFFSET $3 LIMIT $4"
            );
            let rows: Vec<ArtifactRow> = sqlx::query_as(AssertSqlSafe(sql))
                .bind(repository_id)
                .bind(&name)
                .bind(offset)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", &name))?;

            let total: Option<i64> = sqlx::query_scalar(
                "SELECT COUNT(*) FROM artifacts \
                 WHERE repository_id = $1 AND name = $2",
            )
            .bind(repository_id)
            .bind(&name)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Artifact", &name))?;

            let items: Vec<Artifact> = rows
                .into_iter()
                .map(Artifact::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Page {
                items,
                total: total.unwrap_or(0) as u64,
            })
        })
    }

    fn find_by_name_as_published(
        &self,
        repository_id: Uuid,
        raw_name: &str,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<Artifact>>> {
        let raw = raw_name.to_owned();
        let offset = page.offset as i64;
        let limit = page.limit as i64;
        Box::pin(async move {
            tracing::debug!(
                entity = "Artifact",
                %repository_id,
                raw_name = %raw,
                "find_by_name_as_published"
            );
            // Paginated.
            let sql = format!(
                "SELECT {SELECT_COLS} FROM artifacts \
                 WHERE repository_id = $1 AND name_as_published = $2 \
                   AND is_deleted = false \
                 ORDER BY version \
                 OFFSET $3 LIMIT $4"
            );
            let rows: Vec<ArtifactRow> = sqlx::query_as(AssertSqlSafe(sql))
                .bind(repository_id)
                .bind(&raw)
                .bind(offset)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", &raw))?;

            let total: Option<i64> = sqlx::query_scalar(
                "SELECT COUNT(*) FROM artifacts \
                 WHERE repository_id = $1 AND name_as_published = $2 \
                   AND is_deleted = false",
            )
            .bind(repository_id)
            .bind(&raw)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Artifact", &raw))?;

            let items: Vec<Artifact> = rows
                .into_iter()
                .map(Artifact::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Page {
                items,
                total: total.unwrap_or(0) as u64,
            })
        })
    }

    fn find_canonical_name_by_collision_key<'a>(
        &'a self,
        repository_id: Uuid,
        collision_key: &'a str,
    ) -> BoxFuture<'a, DomainResult<Option<String>>> {
        let key = collision_key.to_owned();
        Box::pin(async move {
            tracing::debug!(
                entity = "Artifact",
                %repository_id,
                collision_key = %key,
                "find_canonical_name_by_collision_key"
            );
            // Fold the stored `name` the same way
            // `FormatHandler::collision_key` folds: lowercase + `_`→`-`.
            // Cargo names are already stored lowercase, so `lower()` is a
            // no-op for the only current caller — but the method signature
            // is format-agnostic, so folding case on the stored side too
            // keeps it correct for any future format whose `collision_key`
            // is `Some` over mixed-case stored names (defensive, ~zero
            // cost). The RETURNED `name` is the verbatim stored form (not
            // lowercased) — the use case compares it against the new
            // crate's canonical name to decide collision. Soft-deleted rows
            // do not reserve a name (mirrors the active read path).
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT name FROM artifacts \
                 WHERE repository_id = $1 \
                   AND replace(lower(name), '_', '-') = $2 \
                   AND is_deleted = false \
                 LIMIT 1",
            )
            .bind(repository_id)
            .bind(&key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Artifact", &key))?;
            Ok(existing)
        })
    }

    fn list_active_for_repo(
        &self,
        repository_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<LimitedList<Artifact>>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "Artifact",
                %repository_id,
                "list_active_for_repo"
            );
            // Drives the retroactive curation pass over previously-active
            // artifacts. Excludes already-rejected rows (retro-block on
            // a rejected artifact is a no-op; the rejection is sticky).
            // `is_deleted = false` for symmetry with the rest of the read
            // path.
            //
            // Over-fetch `LIMIT_LIST_MAX_ITEMS + 1` to detect saturation,
            // then funnel through `LimitedList::from_overfetch` which
            // truncates to the cap and flips `truncated`. The cap is a
            // defence-in-depth ceiling against runaway table growth, not
            // a normal operating mode; callers MUST log a `warn!` when
            // truncation fires.
            let cap = LIMIT_LIST_MAX_ITEMS as i64;
            let sql = format!(
                "SELECT {SELECT_COLS} FROM artifacts \
                 WHERE repository_id = $1 \
                   AND quarantine_status IN ('quarantined', 'released') \
                   AND is_deleted = false \
                 LIMIT $2"
            );
            let rows: Vec<ArtifactRow> = sqlx::query_as(AssertSqlSafe(sql))
                .bind(repository_id)
                .bind(cap + 1)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", "list_active_for_repo"))?;
            let items: Vec<Artifact> = rows
                .into_iter()
                .map(Artifact::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(LimitedList::from_overfetch(items, cap as usize))
        })
    }

    fn package_version_status(
        &self,
        repository_id: Uuid,
        package: &str,
    ) -> BoxFuture<'_, DomainResult<Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>>> {
        let pkg = package.to_owned();
        Box::pin(async move {
            tracing::debug!(
                entity = "Artifact",
                %repository_id,
                package = %pkg,
                "package_version_status"
            );
            // The hot serve-path query for the quarantine-aware index
            // filter. Backed by the covering index `artifacts
            // (repository_id, name) INCLUDE (version, quarantine_status)
            // WHERE NOT is_deleted` — expect an index-only scan, no heap
            // fetch.
            //
            // `version IS NOT NULL` — null-version rows have nothing to
            // advertise via an index serve (structural/sidecar files);
            // the port doc-comment is explicit that callers needing those
            // use `find_by_name_in_repo` instead. Keeping the filter on
            // the DB side preserves the index-only-scan plan and means
            // the Vec we materialise is already the right size.
            //
            // The DB stores `QuarantineStatus::None` as NULL; map
            // accordingly.
            //
            // Select ONLY `version, quarantine_status` — these are
            // exactly the columns in the covering index's INCLUDE list, so
            // the plan stays an index-only scan with no heap fetch on this
            // highest-QPS serve-path read. The previous `quarantine_deadline`
            // column does not exist (the schema stores the immutable anchor
            // `quarantine_window_start`, never a precomputed deadline — see
            // migration `003_artifacts_cas.sql` and
            // `hort_domain::policy::effective_quarantine_deadline`), so every
            // call 500'd with `column "quarantine_deadline" does not exist`.
            //
            // The third tuple element (the live quarantine deadline) is NOT
            // sourced here: the hot index-serve / prefetch callers ignore it,
            // and Discovery — the only consumer that needs it — reads the
            // anchor via the dedicated `package_version_anchors` query and
            // computes the deadline at the use-case layer. This path returns
            // `None` for the third element by design.
            let rows: Vec<(String, Option<String>)> = sqlx::query_as(
                "SELECT version, quarantine_status \
                 FROM artifacts \
                 WHERE repository_id = $1 AND name = $2 \
                   AND NOT is_deleted \
                   AND version IS NOT NULL",
            )
            .bind(repository_id)
            .bind(&pkg)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Artifact", &pkg))?;

            let mut triples: Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)> =
                Vec::with_capacity(rows.len());
            for (version, status_str) in rows {
                let status = status_str
                    .as_deref()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(QuarantineStatus::None);
                triples.push((version, status, None));
            }
            Ok(triples)
        })
    }

    fn package_version_anchors(
        &self,
        repository_id: Uuid,
        package: &str,
    ) -> BoxFuture<'_, DomainResult<Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>>> {
        let pkg = package.to_owned();
        Box::pin(async move {
            tracing::debug!(
                entity = "Artifact",
                %repository_id,
                package = %pkg,
                "package_version_anchors"
            );
            // Discovery-only read: per-version status PLUS the immutable
            // quarantine anchor `quarantine_window_start`. Unlike
            // `package_version_status` (the index-only serve path), this
            // reads the anchor column (a heap fetch) and is called only
            // by `DiscoveryUseCase` (low-QPS). The live deadline is
            // computed at the use-case layer via
            // `effective_quarantine_deadline(anchor, duration)` — never
            // stored, so a later `quarantineDuration` edit takes effect
            // without a backfill.
            let rows: Vec<(String, Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
                "SELECT version, quarantine_status, quarantine_window_start \
                 FROM artifacts \
                 WHERE repository_id = $1 AND name = $2 \
                   AND NOT is_deleted \
                   AND version IS NOT NULL",
            )
            .bind(repository_id)
            .bind(&pkg)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Artifact", &pkg))?;

            let mut triples: Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)> =
                Vec::with_capacity(rows.len());
            for (version, status_str, anchor) in rows {
                let status = status_str
                    .as_deref()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(QuarantineStatus::None);
                triples.push((version, status, anchor));
            }
            Ok(triples)
        })
    }

    fn find_pypi_wheels_without_kind(
        &self,
        kind: &str,
        limit: u32,
    ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>> {
        let kind = kind.to_owned();
        let limit = limit as i64;
        Box::pin(async move {
            tracing::debug!(entity = "Artifact", %kind, %limit, "find_pypi_wheels_without_kind");
            // Backfill candidacy. Wheels-only (`path LIKE '%.whl'`) AND
            // no `content_references` row of the given kind. The
            // `NOT EXISTS` correlated subquery is index-friendly —
            // `content_references` has a UNIQUE constraint on
            // `(repository_id, source_artifact_id, kind)`, so the EXISTS
            // probe is a single index dive per candidate row. The
            // `is_deleted = false` filter matches the rest of the read
            // path; a soft-deleted wheel is not a backfill target.
            //
            // Resumable by construction (no cursor, no "claimed" marker):
            // a failed batch leaves the candidate set unchanged; the next
            // invocation re-derives the same set minus rows that landed
            // a `wheel_metadata` ContentReference during this run.
            let sql = format!(
                "SELECT {SELECT_COLS} FROM artifacts \
                 WHERE path LIKE '%.whl' \
                   AND is_deleted = false \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM content_references \
                       WHERE source_artifact_id = artifacts.id \
                         AND kind = $1 \
                   ) \
                 ORDER BY id \
                 LIMIT $2"
            );
            let rows: Vec<ArtifactRow> = sqlx::query_as(AssertSqlSafe(sql))
                .bind(&kind)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", "find_pypi_wheels_without_kind"))?;
            let items: Vec<Artifact> = rows
                .into_iter()
                .map(Artifact::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(items)
        })
    }

    fn find_oci_image_manifests_without_kind(
        &self,
        kind: &str,
        limit: u32,
    ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>> {
        let kind = kind.to_owned();
        let limit = limit as i64;
        Box::pin(async move {
            tracing::debug!(
                entity = "Artifact",
                %kind,
                %limit,
                "find_oci_image_manifests_without_kind"
            );
            // Backfill candidacy. Manifest-shaped rows only (`path LIKE
            // 'manifests/sha256:%'`, the coords convention
            // `hort-http-oci::coords` writes) AND no `content_references`
            // row of the given kind (in practice `oci_config`) AND NOT an
            // image index — discriminated on the stored media type
            // (`artifact_metadata.metadata->>'oci_media_type'`, mirroring
            // `hort-http-oci::manifests::resolve_media_type`'s read). A
            // row with no `artifact_metadata` row at all, or one whose
            // `oci_media_type` field is absent, is NOT excluded — that
            // mirrors `resolve_media_type`'s own fallback to the
            // single-image default and is exactly the pre-metadata-
            // migration shape this backfill targets.
            let sql = format!(
                "SELECT {SELECT_COLS} FROM artifacts \
                 WHERE path LIKE 'manifests/sha256:%' \
                   AND is_deleted = false \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM content_references \
                       WHERE source_artifact_id = artifacts.id \
                         AND kind = $1 \
                   ) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM artifact_metadata \
                       WHERE artifact_id = artifacts.id \
                         AND metadata->>'oci_media_type' IN ($3, $4) \
                   ) \
                 ORDER BY id \
                 LIMIT $2"
            );
            let rows: Vec<ArtifactRow> = sqlx::query_as(AssertSqlSafe(sql))
                .bind(&kind)
                .bind(limit)
                .bind(hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE)
                .bind(hort_domain::oci::DOCKER_MANIFEST_LIST_MEDIA_TYPE)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "Artifact", "find_oci_image_manifests_without_kind")
                })?;
            let items: Vec<Artifact> = rows
                .into_iter()
                .map(Artifact::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(items)
        })
    }

    fn list_rejected_for_policy(
        &self,
        policy_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<LimitedList<Artifact>>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "Artifact",
                %policy_id,
                "list_rejected_for_policy"
            );
            // Drives the post-exclusion-add re-evaluation pass.
            //
            // "Active scan-policy" is a runtime resolution rather than a
            // denormalized column on `artifacts` — repo-scoped policies
            // win over global, mirroring
            // `QuarantineUseCase::resolve_active_policy_for_repo`. The
            // SQL join below encodes the same rule:
            //   1. If `policy_id` is a repo-scoped policy, return rejected
            //      artifacts in that repo only.
            //   2. If `policy_id` is global, return rejected artifacts in
            //      every repo NOT shadowed by a non-archived repo-scoped
            //      policy.
            //
            // Pre-release simplification: in-memory filter fallback would
            // also work given the rejected set is expected ≪ 1k, but
            // delegating to the policy_projections table keeps the
            // shadowing rule in one place (the SQL) rather than splitting
            // it across two adapters. The query touches at most three
            // small tables (artifacts, policy_projections × 2) so the
            // planner-side cost is dominated by the artifacts scan.
            //
            // Over-fetch `LIMIT_LIST_MAX_ITEMS + 1` and funnel through
            // `LimitedList::from_overfetch`. See `list_active_for_repo`
            // for the cap-as-defence-in-depth rationale.
            let cap = LIMIT_LIST_MAX_ITEMS as i64;
            let sql = format!(
                r#"SELECT {SELECT_COLS} FROM artifacts a
                   WHERE a.quarantine_status = 'rejected'
                     AND a.is_deleted = false
                     AND (
                       -- Repo-scoped policy: artifact's repo must match
                       -- the policy's `scope.Repository` UUID.
                       EXISTS (
                         SELECT 1 FROM policy_projections p
                         WHERE p.policy_id = $1
                           AND p.archived = false
                           AND p.scope ? 'Repository'
                           AND (p.scope->>'Repository')::uuid = a.repository_id
                       )
                       OR
                       -- Global policy: artifact's repo must NOT be
                       -- shadowed by a non-archived repo-scoped policy.
                       (
                         EXISTS (
                           SELECT 1 FROM policy_projections p
                           WHERE p.policy_id = $1
                             AND p.archived = false
                             AND p.scope ? 'Global'
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM policy_projections p2
                           WHERE p2.archived = false
                             AND p2.scope ? 'Repository'
                             AND (p2.scope->>'Repository')::uuid = a.repository_id
                         )
                       )
                     )
                   LIMIT $2"#
            );
            let rows: Vec<ArtifactRow> = sqlx::query_as(AssertSqlSafe(sql))
                .bind(policy_id)
                .bind(cap + 1)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", "list_rejected_for_policy"))?;
            let items: Vec<Artifact> = rows
                .into_iter()
                .map(Artifact::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(LimitedList::from_overfetch(items, cap as usize))
        })
    }

    fn list_active_for_policy(
        &self,
        policy_id: Uuid,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<Artifact>>> {
        let offset = page.offset as i64;
        let limit = page.limit as i64;
        Box::pin(async move {
            tracing::debug!(
                entity = "Artifact",
                %policy_id,
                "list_active_for_policy"
            );
            // The complement of `list_rejected_for_policy` — the ADR 0041
            // tighten direction. The WHERE clause that resolves an
            // artifact's repo to `policy_id` (repo-scoped wins over global,
            // mirroring `QuarantineUseCase::resolve_active_policy_for_repo`)
            // is identical; only the leading status predicate differs
            // (`quarantine_status IN ('quarantined','released')` instead of
            // `= 'rejected'`).
            //
            // PAGINATED, not capped. Unlike the loosen direction (a capped
            // `LimitedList` whose truncation merely defers a few would-be
            // releases — fail-safe), a cap here would be fail-OPEN: a
            // now-failing artifact past the cap would keep serving. The
            // application pass walks pages until exhaustion. A stable
            // `ORDER BY id` makes the OFFSET/LIMIT window skip- and
            // duplicate-free across pages.
            const SCOPE_PREDICATE: &str = r#"
                a.quarantine_status IN ('quarantined', 'released')
                AND a.is_deleted = false
                AND (
                  EXISTS (
                    SELECT 1 FROM policy_projections p
                    WHERE p.policy_id = $1
                      AND p.archived = false
                      AND p.scope ? 'Repository'
                      AND (p.scope->>'Repository')::uuid = a.repository_id
                  )
                  OR
                  (
                    EXISTS (
                      SELECT 1 FROM policy_projections p
                      WHERE p.policy_id = $1
                        AND p.archived = false
                        AND p.scope ? 'Global'
                    )
                    AND NOT EXISTS (
                      SELECT 1 FROM policy_projections p2
                      WHERE p2.archived = false
                        AND p2.scope ? 'Repository'
                        AND (p2.scope->>'Repository')::uuid = a.repository_id
                    )
                  )
                )
            "#;
            let sql = format!(
                "SELECT {SELECT_COLS} FROM artifacts a \
                 WHERE {SCOPE_PREDICATE} \
                 ORDER BY a.id \
                 OFFSET $2 LIMIT $3"
            );
            let rows: Vec<ArtifactRow> = sqlx::query_as(AssertSqlSafe(sql))
                .bind(policy_id)
                .bind(offset)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", "list_active_for_policy"))?;

            let count_sql = format!("SELECT COUNT(*) FROM artifacts a WHERE {SCOPE_PREDICATE}");
            let total: Option<i64> = sqlx::query_scalar(AssertSqlSafe(count_sql))
                .bind(policy_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Artifact", "list_active_for_policy_count"))?;

            let items: Vec<Artifact> = rows
                .into_iter()
                .map(Artifact::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Page {
                items,
                total: total.unwrap_or(0) as u64,
            })
        })
    }
}

impl PgArtifactRepository {
    /// Save an artifact within an existing transaction.
    pub(crate) async fn save_in_tx(
        &self,
        tx: &mut PgUnitOfWork,
        artifact: &Artifact,
    ) -> DomainResult<()> {
        tracing::debug!(entity = "Artifact", id = %artifact.id, "save_in_tx");
        let quarantine_str = match artifact.quarantine_status {
            QuarantineStatus::None => None,
            other => Some(other.to_string()),
        };
        let storage_key = artifact.sha256_checksum.as_ref();

        bind_artifact_params(
            sqlx::query(UPSERT_SQL),
            artifact,
            &quarantine_str,
            storage_key,
        )
        .execute(tx.conn())
        .await
        .map_err(|e| map_sqlx_error(&e, "Artifact", &artifact.id.to_string()))?;

        Ok(())
    }

    /// Column-scoped, **prior-status-conditional** UPDATE for a verdict
    /// transition (scan / provenance — issues #90 and #108).
    ///
    /// Writes ONLY `quarantine_status` + `updated_at`, never the full row
    /// (#90): verdict application follows a slow scan-execution /
    /// bundle-fetch round trip after the artifact was loaded, so the
    /// caller's in-memory snapshot of every OTHER column (most critically
    /// `quarantine_window_start`, the quarantine anchor) can be stale by
    /// commit time. A full-row `save_in_tx` write-back would clobber
    /// whatever a concurrently-committed transition wrote to those columns
    /// in the meantime.
    ///
    /// #90 left `quarantine_status` ITSELF — the security-load-bearing
    /// column — written unconditionally from that same stale snapshot, so
    /// a signed image that also tripped a scan policy could resurrect
    /// `Rejected → Quarantined` and then timer-release (#108 H2b). The
    /// UPDATE is therefore predicated on the row still holding the status
    /// the caller LOADED (`prior_status`), via `IS NOT DISTINCT FROM` —
    /// NOT `=` — because `QuarantineStatus::None` is stored as SQL `NULL`
    /// and `NULL = NULL` is `NULL`, never true.
    ///
    /// ## The zero-rows split
    ///
    /// Zero affected rows is ambiguous — the id may be absent, or present
    /// with a changed status — and the two must NOT collapse: a
    /// genuinely-absent id is [`DomainError::NotFound`] (a verdict can
    /// only apply to an already-ingested artifact), while a present row
    /// whose status moved under us is [`DomainError::Conflict`] (the
    /// losing verdict is re-derivable; the caller retries or re-runs).
    /// A single statement disambiguates race-free: the `existing` CTE
    /// reads the pre-UPDATE row under the SAME statement snapshot as the
    /// `updated` CTE's write, so no other transaction can commit between
    /// the two reads (a follow-up `SELECT` after the UPDATE could, and
    /// would misreport a concurrently-deleted row as `NotFound` when it
    /// was really a `Conflict`).
    pub(crate) async fn save_verdict_status_in_tx(
        &self,
        tx: &mut PgUnitOfWork,
        artifact_id: Uuid,
        quarantine_status: QuarantineStatus,
        updated_at: DateTime<Utc>,
        prior_status: QuarantineStatus,
    ) -> DomainResult<()> {
        tracing::debug!(
            entity = "Artifact",
            id = %artifact_id,
            "save_verdict_status_in_tx"
        );
        let to_sql = |s: QuarantineStatus| match s {
            QuarantineStatus::None => None,
            other => Some(other.to_string()),
        };
        let quarantine_str = to_sql(quarantine_status);
        let prior_str = to_sql(prior_status);

        let (existed, updated): (bool, bool) = sqlx::query_as(
            "WITH existing AS (
                 SELECT 1 FROM artifacts WHERE id = $3
             ),
             updated AS (
                 UPDATE artifacts SET quarantine_status = $1, updated_at = $2
                 WHERE id = $3 AND quarantine_status IS NOT DISTINCT FROM $4
                 RETURNING 1
             )
             SELECT EXISTS (SELECT 1 FROM existing), EXISTS (SELECT 1 FROM updated)",
        )
        .bind(quarantine_str)
        .bind(updated_at)
        .bind(artifact_id)
        .bind(prior_str)
        .fetch_one(tx.conn())
        .await
        .map_err(|e| map_sqlx_error(&e, "Artifact", &artifact_id.to_string()))?;

        if updated {
            return Ok(());
        }
        if !existed {
            return Err(DomainError::NotFound {
                entity: "Artifact",
                id: artifact_id.to_string(),
            });
        }
        // Present, but its status is no longer `prior_status` — a
        // concurrent verdict/transition won. Fail closed: the stale
        // verdict must not overwrite the newer status. `warn!` (not
        // `error!`) — recoverable and expected under contention, matching
        // the `commit_transition` conflict convention.
        tracing::warn!(
            entity = "Artifact",
            id = %artifact_id,
            ?prior_status,
            attempted = ?quarantine_status,
            "verdict status write conflicted: quarantine_status changed since load"
        );
        Err(DomainError::Conflict(format!(
            "artifact {artifact_id} quarantine_status changed concurrently \
             (expected {prior_status}); verdict not applied"
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests — DB-backed integration tests covering pagination + LIMIT bounds.
// Runtime self-skip (issue #94): `maybe_pool()` returns `None` when
// `DATABASE_URL` is unset, and each test does
// `let Some(pool) = maybe_pool().await else { return; };` — a clean,
// fast no-op under plain `cargo test`, full execution when
// `DATABASE_URL` is wired (e.g. `test:integration` CI). Every DB-touching
// test carries `#[serial(hort_pg_db)]`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
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
        let key = format!("it-artpag-{}", id.simple());
        sqlx::query(
            r#"INSERT INTO repositories (
                   id, key, name, format, repo_type, storage_backend, storage_path,
                   replication_priority
               ) VALUES (
                   $1, $2, $3,
                   'pypi'::repository_format,
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

    async fn cleanup_repo(pool: &PgPool, repo: Uuid) {
        // DELETE artifacts first to dodge FK constraints.
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(pool)
            .await;
    }

    /// Generate a deterministic 64-character lowercase hex string from a
    /// seed integer. The artifacts table has uniqueness expectations on
    /// `(checksum_sha256)` in places, so each seeded row needs a distinct
    /// hex blob. We avoid bringing in `sha2` as a dev-dep just for tests
    /// — the `Artifact::try_from(ArtifactRow)` path only validates
    /// 64 lowercase hex chars (per `ContentHash`), not actual SHA-2.
    fn deterministic_hex64(seed: usize) -> String {
        // Hash via the std library's `DefaultHasher` for distinctness
        // within a test run, then expand to 64 hex chars by combining
        // the 64-bit hash, its swap, and the input — collision-free for
        // up to ~1e8 distinct seeds, which is far above the test scale.
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut h);
        let h1 = h.finish();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        (seed.wrapping_add(1)).hash(&mut h2);
        let h2v = h2.finish();
        let mut h3 = std::collections::hash_map::DefaultHasher::new();
        (seed.wrapping_mul(2654435761)).hash(&mut h3);
        let h3v = h3.finish();
        let mut h4 = std::collections::hash_map::DefaultHasher::new();
        (seed.wrapping_mul(0x9E3779B9)).hash(&mut h4);
        let h4v = h4.finish();
        format!("{h1:016x}{h2v:016x}{h3v:016x}{h4v:016x}")
    }

    /// Bulk-insert N artifacts under one repo with the given name. Uses
    /// `name_as_published = name` so callers can hit either of the
    /// `find_by_name_*` paths without re-seeding. Versions are
    /// zero-padded so the natural lexicographic `ORDER BY version` is
    /// deterministic.
    async fn seed_artifacts_with_name(pool: &PgPool, repo: Uuid, name: &str, n: usize) {
        for i in 0..n {
            let id = Uuid::new_v4();
            let path = format!("simple/{name}/{name}-{i:08}.tar.gz");
            let version = format!("{i:08}");
            let sha256 = deterministic_hex64(i ^ (name.len() << 40));
            sqlx::query(
                r#"INSERT INTO artifacts (
                       id, repository_id, name, name_as_published, version, path,
                       size_bytes, checksum_sha256, content_type, storage_key
                   ) VALUES (
                       $1, $2, $3, $3, $4, $5,
                       0, $6, 'application/octet-stream', $6
                   )"#,
            )
            .bind(id)
            .bind(repo)
            .bind(name)
            .bind(&version)
            .bind(&path)
            .bind(&sha256)
            .execute(pool)
            .await
            .expect("seed artifact insert");
        }
    }

    /// Bulk-insert N "active" artifacts (`quarantine_status` = 'released'
    /// for simplicity — the SQL accepts both `quarantined` and `released`).
    async fn seed_active_artifacts(pool: &PgPool, repo: Uuid, n: usize) {
        for i in 0..n {
            let id = Uuid::new_v4();
            let path = format!("simple/active/active-{i:08}.tar.gz");
            let sha256 = deterministic_hex64(i ^ 0xACE_F00D);
            sqlx::query(
                r#"INSERT INTO artifacts (
                       id, repository_id, name, name_as_published, version, path,
                       size_bytes, checksum_sha256, content_type, storage_key,
                       quarantine_status
                   ) VALUES (
                       $1, $2, 'active-name', 'active-name', $3, $4,
                       0, $5, 'application/octet-stream', $5,
                       'released'
                   )"#,
            )
            .bind(id)
            .bind(repo)
            .bind(format!("{i:08}"))
            .bind(&path)
            .bind(&sha256)
            .execute(pool)
            .await
            .expect("seed active artifact");
        }
    }

    /// `find_by_name_in_repo` honours `PageRequest` — request a page of
    /// `limit` items off a seed > limit; the returned page has
    /// `items.len() == limit` AND the total reflects the full row set.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_name_in_repo_caps_at_default_page_size() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        // Seed 50 versions, request the first 20 (PageRequest::default).
        seed_artifacts_with_name(&pool, repo_id, "many", 50).await;

        let r = PgArtifactRepository::new(pool.clone());
        let page = r
            .find_by_name_in_repo(repo_id, "many", PageRequest::default())
            .await
            .expect("page fetch");

        assert_eq!(page.items.len(), 20, "page size matches default limit");
        assert_eq!(page.total, 50, "total reflects the full row set");

        cleanup_repo(&pool, repo_id).await;
    }

    /// Walking pages of `find_by_name_in_repo` collects every row exactly
    /// once across the entire set. Asserts:
    ///   - cumulative count equals N,
    ///   - no duplicate IDs,
    ///   - the ordering is stable (sorted by version, which is
    ///     zero-padded so lexicographic == numeric).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_name_in_repo_paginates_through_all_results() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        seed_artifacts_with_name(&pool, repo_id, "walk", 75).await;

        let r = PgArtifactRepository::new(pool.clone());
        let mut seen: Vec<Uuid> = Vec::new();
        let mut offset: u64 = 0;
        let limit: u64 = 20;
        loop {
            let page = r
                .find_by_name_in_repo(repo_id, "walk", PageRequest::new(offset, limit))
                .await
                .expect("page fetch");
            if page.items.is_empty() {
                break;
            }
            for a in &page.items {
                seen.push(a.id);
            }
            if (page.items.len() as u64) < limit {
                break;
            }
            offset += page.items.len() as u64;
        }
        assert_eq!(seen.len(), 75, "every row visited exactly once");
        let unique: std::collections::HashSet<Uuid> = seen.iter().copied().collect();
        assert_eq!(unique.len(), 75, "no duplicates across pages");

        cleanup_repo(&pool, repo_id).await;
    }

    /// `PageRequest::new` caps `limit` at the workspace `MAX_LIMIT`
    /// (1 000). Even when a caller asks for 5 000, the materialised
    /// page never exceeds the cap. The repository inherits this
    /// boundary by binding `page.limit` directly.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_name_in_repo_max_page_size_capped() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        // Seed enough to hit the cap; 1500 > 1000 = MAX_LIMIT.
        seed_artifacts_with_name(&pool, repo_id, "cap", 1_500).await;

        let r = PgArtifactRepository::new(pool.clone());
        let page = r
            .find_by_name_in_repo(repo_id, "cap", PageRequest::new(0, 5_000))
            .await
            .expect("page fetch");
        // MAX_LIMIT is 1000; the request was 5000, the page must be ≤ 1000.
        assert!(
            page.items.len() <= 1_000,
            "page size capped at workspace MAX_LIMIT (1000); got {}",
            page.items.len()
        );

        cleanup_repo(&pool, repo_id).await;
    }

    /// At `LIMIT_LIST_MAX_ITEMS + 1` rows the adapter truncates to
    /// exactly the cap and flips `truncated`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_active_for_repo_truncates_at_limit_list_max_items() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        // Seed cap + 1 active artifacts.
        seed_active_artifacts(&pool, repo_id, LIMIT_LIST_MAX_ITEMS as usize + 1).await;

        let r = PgArtifactRepository::new(pool.clone());
        let list = r
            .list_active_for_repo(repo_id)
            .await
            .expect("list_active_for_repo");
        assert_eq!(list.items.len(), LIMIT_LIST_MAX_ITEMS as usize);
        assert!(list.truncated);

        cleanup_repo(&pool, repo_id).await;
    }

    /// Below the cap, `truncated` stays false. Boundary check on the
    /// over-fetch detection — fetching 2 000 of 2 000 must not surface a
    /// false-positive truncation signal.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_active_for_repo_does_not_truncate_below_cap() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        seed_active_artifacts(&pool, repo_id, 2_000).await;

        let r = PgArtifactRepository::new(pool.clone());
        let list = r
            .list_active_for_repo(repo_id)
            .await
            .expect("list_active_for_repo");
        assert_eq!(list.items.len(), 2_000);
        assert!(
            !list.truncated,
            "below-cap result must not trip the truncated flag"
        );

        cleanup_repo(&pool, repo_id).await;
    }

    /// Seed a single artifact with an explicit quarantine status string,
    /// version, and `is_deleted` flag. Used by the
    /// `package_version_status` round-trip below; the existing helpers
    /// don't cover quarantine + soft-delete + null-version combinations
    /// in one shot, and the query exercises all three branches.
    #[allow(clippy::too_many_arguments)]
    async fn seed_artifact_status(
        pool: &PgPool,
        repo: Uuid,
        name: &str,
        version: Option<&str>,
        status: Option<&str>,
        is_deleted: bool,
        seed: usize,
    ) {
        let id = Uuid::new_v4();
        let v_path = version.unwrap_or("nover");
        let path = format!("simple/{name}/{name}-{v_path}-{seed:04}.tar.gz");
        let sha256 = deterministic_hex64(seed ^ 0x1247_BEEF_usize);
        sqlx::query(
            r#"INSERT INTO artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   quarantine_status, is_deleted
               ) VALUES (
                   $1, $2, $3, $3, $4, $5,
                   0, $6, 'application/octet-stream', $6,
                   $7, $8
               )"#,
        )
        .bind(id)
        .bind(repo)
        .bind(name)
        .bind(version)
        .bind(&path)
        .bind(&sha256)
        .bind(status)
        .bind(is_deleted)
        .execute(pool)
        .await
        .expect("seed status artifact");
    }

    /// Round-trip test for [`ArtifactRepository::package_version_status`].
    ///
    /// Seeds artifacts spanning every relevant axis the index-serve
    /// filter cares about:
    ///   - matching `(repository_id, name)` with versions in every
    ///     quarantine status (None → SQL NULL, Quarantined, Released,
    ///     Rejected, ScanIndeterminate),
    ///   - a soft-deleted row (`is_deleted = true`) that MUST be excluded,
    ///   - a null-version row that MUST be excluded (the serve filter
    ///     advertises versions; a null-version row has nothing to
    ///     advertise — see the port doc-comment),
    ///   - an artifact under a different `name` in the same repo
    ///     (boundary check on the package filter),
    ///   - an artifact under the same `name` in a different repo
    ///     (boundary check on the repository filter).
    ///
    /// Verifies the adapter returns only the in-scope rows with the
    /// correct `(version, QuarantineStatus)` pairings. `#[serial]` on the
    /// crate-wide `hort_pg_db` key per CLAUDE.md DB-backed test isolation
    /// contract.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn package_version_status_returns_repo_scoped_pairs_excluding_deleted_and_null_version() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_a = seed_repo(&pool).await;
        let repo_b = seed_repo(&pool).await;

        // repo_a / "leftpad": one row per quarantine status, plus an
        // excluded soft-deleted row + an excluded null-version row.
        seed_artifact_status(&pool, repo_a, "leftpad", Some("1.0.0"), None, false, 0).await;
        seed_artifact_status(
            &pool,
            repo_a,
            "leftpad",
            Some("1.1.0"),
            Some("quarantined"),
            false,
            1,
        )
        .await;
        seed_artifact_status(
            &pool,
            repo_a,
            "leftpad",
            Some("1.2.0"),
            Some("released"),
            false,
            2,
        )
        .await;
        seed_artifact_status(
            &pool,
            repo_a,
            "leftpad",
            Some("1.3.0"),
            Some("rejected"),
            false,
            3,
        )
        .await;
        seed_artifact_status(
            &pool,
            repo_a,
            "leftpad",
            Some("1.4.0"),
            Some("scan_indeterminate"),
            false,
            4,
        )
        .await;
        // Soft-deleted — MUST be excluded.
        seed_artifact_status(
            &pool,
            repo_a,
            "leftpad",
            Some("9.9.0"),
            Some("released"),
            true,
            5,
        )
        .await;
        // Null version — MUST be excluded.
        seed_artifact_status(&pool, repo_a, "leftpad", None, Some("released"), false, 6).await;
        // Different name in the same repo — MUST be excluded.
        seed_artifact_status(
            &pool,
            repo_a,
            "other-pkg",
            Some("1.0.0"),
            Some("released"),
            false,
            7,
        )
        .await;
        // Same name, different repo — MUST be excluded.
        seed_artifact_status(
            &pool,
            repo_b,
            "leftpad",
            Some("2.0.0"),
            Some("released"),
            false,
            8,
        )
        .await;

        let r = PgArtifactRepository::new(pool.clone());
        let triples = r
            .package_version_status(repo_a, "leftpad")
            .await
            .expect("package_version_status");

        // Order is not guaranteed by the adapter — sort before asserting.
        // Drop the third element (`quarantine_until`) for this comparison
        // — the `seed_artifact_status` helper writes the
        // `quarantine_deadline` column to `NULL` regardless of status, so
        // the status round-trip is the right scope for this test.
        // Coverage of `quarantine_until` lives in the `DiscoveryUseCase`
        // tests (`hort-app`).
        let mut got: Vec<(String, QuarantineStatus)> =
            triples.into_iter().map(|(v, s, _)| (v, s)).collect();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        let want: Vec<(String, QuarantineStatus)> = vec![
            ("1.0.0".to_string(), QuarantineStatus::None),
            ("1.1.0".to_string(), QuarantineStatus::Quarantined),
            ("1.2.0".to_string(), QuarantineStatus::Released),
            ("1.3.0".to_string(), QuarantineStatus::Rejected),
            ("1.4.0".to_string(), QuarantineStatus::ScanIndeterminate),
        ];
        assert_eq!(got, want);

        cleanup_repo(&pool, repo_a).await;
        cleanup_repo(&pool, repo_b).await;
    }

    /// Sanity check: a never-seen package returns an empty vec, not an
    /// error. Documents the contract for the `ReleasedOnly` index-mode
    /// cold-start: an empty serve set means "nothing to advertise", not
    /// "lookup failure".
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn package_version_status_unknown_package_returns_empty_vec() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let r = PgArtifactRepository::new(pool.clone());
        let triples = r
            .package_version_status(repo, "never-seen-package")
            .await
            .expect("package_version_status");
        assert!(triples.is_empty());
        cleanup_repo(&pool, repo).await;
    }

    /// `upstream_published_at` round-trips through the
    /// `bind_artifact_params` write path and the `SELECT_COLS` +
    /// `ArtifactRow` read path. Two artifacts in one serial test: one
    /// with a known `Some(timestamp)`, one with `None`. The field is
    /// nullable (absent ⇒ "no upstream-published-at known"), so the
    /// `None` round-trip is load-bearing — a future migration that
    /// drifted to `NOT NULL` (or a bind that silently substituted a
    /// default) would fail this test.
    ///
    /// The clock-skew clamp lives in the application layer
    /// (`min(published, ingested)`), NOT here — the adapter stores the
    /// untrusted value verbatim for audit.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn artifact_upstream_published_at_round_trips() {
        use crate::event_store::PgEventStore;
        use hort_domain::entities::artifact::Artifact;

        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;

        // Construct an event store so we can mint a unit-of-work for
        // the `save_in_tx` write path. The startup checks pass against
        // the freshly-migrated test DB.
        let event_store = PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new");
        let repo = PgArtifactRepository::new(pool.clone());

        // A deterministic, microsecond-precision timestamp — TIMESTAMPTZ
        // round-trips at microsecond resolution; using `Utc::now()` raw
        // can fail equality by sub-microsecond loss on some platforms.
        let upstream_ts: DateTime<Utc> = "2025-04-01T12:34:56Z".parse().unwrap();

        // ---- Some(ts) round-trip ----
        let id_some = Uuid::new_v4();
        let sha_some = deterministic_hex64(0x1234_5678);
        let artifact_some = Artifact {
            id: id_some,
            repository_id: repo_id,
            name: "with-upstream".into(),
            name_as_published: "with-upstream".into(),
            version: Some("1.0.0".into()),
            path: format!("with-upstream/1.0.0/{id_some}.tar.gz"),
            size_bytes: 0,
            sha256_checksum: sha_some.parse().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: Some(upstream_ts),
            uploaded_by: None,
            is_deleted: false,
            created_at: upstream_ts,
            updated_at: upstream_ts,
        };
        let mut uow = event_store
            .begin_unit_of_work()
            .await
            .expect("begin uow (some)");
        repo.save_in_tx(&mut uow, &artifact_some)
            .await
            .expect("save_in_tx (some)");
        uow.commit().await.expect("commit (some)");

        let read_some = repo.find_by_id(id_some).await.expect("find_by_id (some)");
        assert_eq!(
            read_some.upstream_published_at,
            Some(upstream_ts),
            "Some(ts) must round-trip verbatim"
        );

        // ---- None round-trip ----
        let id_none = Uuid::new_v4();
        let sha_none = deterministic_hex64(0x8765_4321);
        let artifact_none = Artifact {
            id: id_none,
            repository_id: repo_id,
            name: "no-upstream".into(),
            name_as_published: "no-upstream".into(),
            version: Some("1.0.0".into()),
            path: format!("no-upstream/1.0.0/{id_none}.tar.gz"),
            size_bytes: 0,
            sha256_checksum: sha_none.parse().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: upstream_ts,
            updated_at: upstream_ts,
        };
        let mut uow = event_store
            .begin_unit_of_work()
            .await
            .expect("begin uow (none)");
        repo.save_in_tx(&mut uow, &artifact_none)
            .await
            .expect("save_in_tx (none)");
        uow.commit().await.expect("commit (none)");

        let read_none = repo.find_by_id(id_none).await.expect("find_by_id (none)");
        assert_eq!(
            read_none.upstream_published_at, None,
            "None must round-trip — the column is nullable and the bind \
             must not silently substitute a default"
        );

        cleanup_repo(&pool, repo_id).await;
    }

    /// issue #90 — `save_verdict_status_in_tx` must write ONLY
    /// `quarantine_status` + `updated_at`, never the full row: a verdict
    /// commit (scan / provenance) built from a snapshot loaded before a
    /// concurrent transition landed must not clobber that transition's
    /// columns — most critically `quarantine_window_start`, the
    /// quarantine anchor. Pins the real Postgres UPDATE against every
    /// other artifact column, not just the anchor.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_verdict_status_in_tx_does_not_clobber_other_columns() {
        use crate::event_store::PgEventStore;
        use hort_domain::entities::artifact::Artifact;

        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;

        let event_store = PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new");
        let repo = PgArtifactRepository::new(pool.clone());

        // Seed a full row via the ordinary full-row write path — as if
        // ingest had committed it, already carrying a quarantine anchor
        // (simulating the concurrent quarantine transition having
        // already landed by the time the verdict commit below runs).
        let id = Uuid::new_v4();
        let sha256 = deterministic_hex64(0xFEED_0090);
        let anchor: DateTime<Utc> = "2025-06-01T00:00:00Z".parse().unwrap();
        let original_updated_at: DateTime<Utc> = "2025-06-01T00:00:00Z".parse().unwrap();
        let artifact = Artifact {
            id,
            repository_id: repo_id,
            name: "verdict-pkg".into(),
            name_as_published: "verdict-pkg".into(),
            version: Some("1.0.0".into()),
            path: format!("verdict-pkg/1.0.0/{id}.tar.gz"),
            size_bytes: 1234,
            sha256_checksum: sha256.parse().unwrap(),
            sha1_checksum: Some("a".repeat(40)),
            md5_checksum: Some("b".repeat(32)),
            content_type: "application/octet-stream".into(),
            quarantine_status: QuarantineStatus::Quarantined,
            rejection_reason: None,
            quarantine_window_start: Some(anchor),
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: original_updated_at,
            updated_at: original_updated_at,
        };
        let mut uow = event_store.begin_unit_of_work().await.expect("begin uow");
        repo.save_in_tx(&mut uow, &artifact)
            .await
            .expect("save_in_tx (seed)");
        uow.commit().await.expect("commit (seed)");

        // The verdict commit: column-scoped write, deciding Rejected.
        // Deliberately does NOT thread `quarantine_window_start` — that's
        // the whole point of the method under test.
        let verdict_updated_at: DateTime<Utc> = "2025-06-01T01:00:00Z".parse().unwrap();
        let mut uow = event_store
            .begin_unit_of_work()
            .await
            .expect("begin uow (verdict)");
        repo.save_verdict_status_in_tx(
            &mut uow,
            id,
            QuarantineStatus::Rejected,
            verdict_updated_at,
            // Prior status == what the seed row holds, so the #108
            // conditional predicate matches and the write proceeds.
            QuarantineStatus::Quarantined,
        )
        .await
        .expect("save_verdict_status_in_tx");
        uow.commit().await.expect("commit (verdict)");

        let saved = repo.find_by_id(id).await.expect("find_by_id");
        assert_eq!(
            saved.quarantine_status,
            QuarantineStatus::Rejected,
            "the verdict's own status change must land"
        );
        assert_eq!(
            saved.updated_at, verdict_updated_at,
            "updated_at must reflect the verdict commit"
        );
        assert_eq!(
            saved.quarantine_window_start,
            Some(anchor),
            "the anchor must survive — a column-scoped verdict commit must not clobber it"
        );
        // Every other column, unrelated to the verdict, must also be
        // untouched — a regression to a full-row UPSERT would clobber
        // these too since the caller of a real verdict commit typically
        // holds a stale in-memory snapshot for them.
        assert_eq!(saved.name, artifact.name);
        assert_eq!(saved.version, artifact.version);
        assert_eq!(saved.path, artifact.path);
        assert_eq!(saved.size_bytes, artifact.size_bytes);
        assert_eq!(saved.sha256_checksum, artifact.sha256_checksum);
        assert_eq!(saved.sha1_checksum, artifact.sha1_checksum);
        assert_eq!(saved.md5_checksum, artifact.md5_checksum);

        cleanup_repo(&pool, repo_id).await;
    }

    /// issue #90 — `save_verdict_status_in_tx` errors `NotFound` rather
    /// than silently no-op-ing when the artifact row does not exist (a
    /// verdict can only ever apply to an already-ingested artifact; a
    /// missing row is an invariant violation, not a benign skip).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_verdict_status_in_tx_errors_not_found_on_missing_row() {
        use crate::event_store::PgEventStore;

        let Some(pool) = maybe_pool().await else {
            return;
        };
        let event_store = PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new");
        let repo = PgArtifactRepository::new(pool.clone());

        let mut uow = event_store.begin_unit_of_work().await.expect("begin uow");
        let err = repo
            .save_verdict_status_in_tx(
                &mut uow,
                Uuid::new_v4(),
                QuarantineStatus::Rejected,
                Utc::now(),
                QuarantineStatus::Quarantined,
            )
            .await
            .expect_err("missing row must error, not silently no-op");
        assert!(
            matches!(err, DomainError::NotFound { .. }),
            "an ABSENT id must stay NotFound — issue #108 added a Conflict arm for a \
             PRESENT row whose status moved, and the two must not collapse; got {err:?}"
        );
    }

    /// Seed one artifact row at `status` and return its id. Shared by the
    /// #108 conditional-UPDATE tests below.
    #[cfg(test)]
    async fn seed_artifact_at_status(
        pool: &PgPool,
        repo_id: Uuid,
        seed: usize,
        status: QuarantineStatus,
    ) -> (Uuid, DateTime<Utc>) {
        use crate::event_store::PgEventStore;
        use hort_domain::entities::artifact::Artifact;

        let event_store = PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new");
        let repo = PgArtifactRepository::new(pool.clone());
        let id = Uuid::new_v4();
        let anchor: DateTime<Utc> = "2025-06-01T00:00:00Z".parse().unwrap();
        let artifact = Artifact {
            id,
            repository_id: repo_id,
            name: "cond-pkg".into(),
            name_as_published: "cond-pkg".into(),
            version: Some("1.0.0".into()),
            path: format!("cond-pkg/1.0.0/{id}.tar.gz"),
            size_bytes: 42,
            sha256_checksum: deterministic_hex64(seed).parse().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: status,
            rejection_reason: None,
            quarantine_window_start: Some(anchor),
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: anchor,
            updated_at: anchor,
        };
        let mut uow = event_store.begin_unit_of_work().await.expect("begin uow");
        repo.save_in_tx(&mut uow, &artifact)
            .await
            .expect("save_in_tx (seed)");
        uow.commit().await.expect("commit (seed)");
        (id, anchor)
    }

    /// issue #108 H2b — the conditional UPDATE must REFUSE a write whose
    /// `prior_status` no longer matches the persisted row, and must
    /// report that as `Conflict`, NOT `NotFound` (the row is present) and
    /// certainly not by overwriting. This is the projection-layer backstop
    /// behind the event-store OCC: it fires even when the append itself
    /// did not conflict.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_verdict_status_in_tx_conflicts_when_prior_status_changed() {
        use crate::event_store::PgEventStore;

        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        // Persisted row is `Rejected` (as if a scan verdict just landed).
        let (id, _anchor) =
            seed_artifact_at_status(&pool, repo_id, 0xFEED_0108, QuarantineStatus::Rejected).await;

        let event_store = PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new");
        let repo = PgArtifactRepository::new(pool.clone());

        // A stale verdict that LOADED `Quarantined` tries to write.
        let mut uow = event_store.begin_unit_of_work().await.expect("begin uow");
        let err = repo
            .save_verdict_status_in_tx(
                &mut uow,
                id,
                QuarantineStatus::Released,
                Utc::now(),
                QuarantineStatus::Quarantined,
            )
            .await
            .expect_err("a changed prior status must refuse the write");
        drop(uow);

        assert!(
            matches!(err, DomainError::Conflict(_)),
            "a PRESENT row whose status moved must be Conflict, not NotFound — the split is \
             the whole point of the CTE; got {err:?}"
        );
        let saved = repo.find_by_id(id).await.expect("find_by_id");
        assert_eq!(
            saved.quarantine_status,
            QuarantineStatus::Rejected,
            "the persisted status must be left exactly as the concurrent writer left it"
        );

        cleanup_repo(&pool, repo_id).await;
    }

    /// issue #108 H2b — `QuarantineStatus::None` is stored as SQL `NULL`,
    /// and `NULL = NULL` is `NULL` (never true), so the predicate MUST use
    /// `IS NOT DISTINCT FROM`. A plain `=` would make every
    /// `None`-prior-status verdict spuriously `Conflict`. Pins that the
    /// NULL-prior case MATCHES and the write lands.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn save_verdict_status_in_tx_matches_null_prior_status() {
        use crate::event_store::PgEventStore;

        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        // Persisted row is `None` → the column is SQL NULL.
        let (id, _anchor) =
            seed_artifact_at_status(&pool, repo_id, 0xFEED_0109, QuarantineStatus::None).await;

        let event_store = PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new");
        let repo = PgArtifactRepository::new(pool.clone());

        let mut uow = event_store.begin_unit_of_work().await.expect("begin uow");
        repo.save_verdict_status_in_tx(
            &mut uow,
            id,
            QuarantineStatus::Rejected,
            Utc::now(),
            QuarantineStatus::None,
        )
        .await
        .expect("a NULL prior status must MATCH via IS NOT DISTINCT FROM, not spuriously conflict");
        uow.commit().await.expect("commit");

        let saved = repo.find_by_id(id).await.expect("find_by_id");
        assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);

        cleanup_repo(&pool, repo_id).await;
    }

    // ---------------------------------------------------------------------
    // find_pypi_wheels_without_kind PG SQL pin
    // ---------------------------------------------------------------------

    /// Seed a single artifact with a specific `path` and optional
    /// `wheel_metadata` ContentReference row for the
    /// `find_pypi_wheels_without_kind` integration tests below. Returns
    /// the artifact's id so the test can correlate the candidate set
    /// against expectations.
    ///
    /// Mirrors `seed_artifact_status`'s direct-insert shape — the test
    /// is asserting the SQL JOIN, not the lifecycle path, so a bare
    /// INSERT keeps the setup minimal and deterministic.
    async fn seed_artifact_at_path(pool: &PgPool, repo: Uuid, path: &str, seed: usize) -> Uuid {
        let id = Uuid::new_v4();
        let sha256 = deterministic_hex64(seed ^ 0xCAFE_BABE_usize);
        sqlx::query(
            r#"INSERT INTO artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key
               ) VALUES (
                   $1, $2, 'wbf-pkg', 'wbf-pkg', $3, $4,
                   0, $5, 'application/octet-stream', $5
               )"#,
        )
        .bind(id)
        .bind(repo)
        .bind(format!("v{seed:08}"))
        .bind(path)
        .bind(&sha256)
        .execute(pool)
        .await
        .expect("seed artifact at path");
        id
    }

    /// Insert a `wheel_metadata` ContentReference row pointing the given
    /// source artifact at an arbitrary (well-formed) content hash —
    /// used to model "this wheel has been backfilled / freshly ingested
    /// already, so the candidacy query MUST exclude it."
    async fn seed_wheel_metadata_ref(
        pool: &PgPool,
        repo_id: Uuid,
        source_artifact_id: Uuid,
        seed: usize,
    ) {
        let target_hash = deterministic_hex64(seed ^ 0xDEAD_BEEF_usize);
        sqlx::query(
            r#"INSERT INTO content_references (
                   repository_id, source_artifact_id, target_content_hash,
                   kind, metadata, recorded_at
               ) VALUES (
                   $1, $2, $3, 'wheel_metadata', '{}'::jsonb, now()
               )"#,
        )
        .bind(repo_id)
        .bind(source_artifact_id)
        .bind(&target_hash)
        .execute(pool)
        .await
        .expect("seed wheel_metadata content_reference");
    }

    /// Empty result on a repo with no wheels at all. Pins the cold-start
    /// no-op (the simplest contract the handler relies on: an empty
    /// candidate set yields summary all-zero).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_pypi_wheels_without_kind_returns_empty_when_no_wheels_exist() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let r = PgArtifactRepository::new(pool.clone());
        let got = r
            .find_pypi_wheels_without_kind("wheel_metadata", 100)
            .await
            .expect("query");
        assert!(got.is_empty(), "no wheels seeded → empty candidate set");
        cleanup_repo(&pool, repo).await;
    }

    /// Mixed seed: two wheels without a `wheel_metadata` row
    /// (candidates), one wheel with a row (NOT a candidate — the NOT
    /// EXISTS predicate prunes it), one sdist (path filter excludes it).
    /// The query MUST return exactly the two un-backfilled wheels.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_pypi_wheels_without_kind_excludes_wheels_with_ref_and_sdists() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        // Two wheels with no wheel_metadata row — candidates.
        let wheel_a =
            seed_artifact_at_path(&pool, repo, "files/wbf_pkg-1.0.0-py3-none-any.whl", 100).await;
        let wheel_b =
            seed_artifact_at_path(&pool, repo, "files/wbf_pkg-1.1.0-py3-none-any.whl", 101).await;

        // One wheel WITH a wheel_metadata row — NOT a candidate.
        let wheel_c =
            seed_artifact_at_path(&pool, repo, "files/wbf_pkg-1.2.0-py3-none-any.whl", 102).await;
        seed_wheel_metadata_ref(&pool, repo, wheel_c, 102).await;

        // One sdist — path filter excludes regardless of content_references.
        let _sdist = seed_artifact_at_path(&pool, repo, "files/wbf_pkg-1.0.0.tar.gz", 103).await;

        let r = PgArtifactRepository::new(pool.clone());
        let got = r
            .find_pypi_wheels_without_kind("wheel_metadata", 100)
            .await
            .expect("query");

        let got_ids: std::collections::HashSet<Uuid> = got.iter().map(|a| a.id).collect();
        let want_ids: std::collections::HashSet<Uuid> = [wheel_a, wheel_b].into_iter().collect();
        assert_eq!(
            got_ids, want_ids,
            "candidate set MUST be exactly the un-backfilled wheels: {got_ids:?} vs want {want_ids:?}"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// `limit` is honoured. Seed 5 candidate wheels, ask for 3; the
    /// adapter MUST return exactly 3 rows (the OFFSET-less LIMIT shape
    /// — no slow walk through the candidate set). Stable ordering is
    /// implicit via `ORDER BY id`; the test does not assert WHICH 3
    /// (the production handler does not care; it re-derives the next
    /// batch on the next invocation).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_pypi_wheels_without_kind_honours_limit() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        for seed in 200..205 {
            let _ =
                seed_artifact_at_path(&pool, repo, &format!("files/limit-{seed}.whl"), seed).await;
        }

        let r = PgArtifactRepository::new(pool.clone());
        let got = r
            .find_pypi_wheels_without_kind("wheel_metadata", 3)
            .await
            .expect("query");
        assert_eq!(got.len(), 3, "LIMIT 3 must yield exactly 3 candidates");

        cleanup_repo(&pool, repo).await;
    }

    /// Soft-deleted wheels are excluded. The handler MUST NOT backfill
    /// a soft-deleted artifact (its lifetime is over; running extract on
    /// it would waste CAS bandwidth and the resulting ContentReference
    /// would be unreachable). Mirrors `is_deleted = false` filter on the
    /// rest of the read path.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_pypi_wheels_without_kind_excludes_soft_deleted_wheels() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        let live = seed_artifact_at_path(&pool, repo, "files/live.whl", 300).await;
        let deleted = seed_artifact_at_path(&pool, repo, "files/dead.whl", 301).await;
        // Mark `deleted` soft-deleted directly via SQL (the
        // `ArtifactRepository` port has no setter — this is a test-
        // local seed concern).
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(deleted)
            .execute(&pool)
            .await
            .expect("soft-delete update");

        let r = PgArtifactRepository::new(pool.clone());
        let got = r
            .find_pypi_wheels_without_kind("wheel_metadata", 100)
            .await
            .expect("query");
        let got_ids: std::collections::HashSet<Uuid> = got.iter().map(|a| a.id).collect();
        assert_eq!(
            got_ids,
            [live].into_iter().collect(),
            "soft-deleted wheel MUST be excluded — got {got_ids:?}"
        );

        cleanup_repo(&pool, repo).await;
    }

    // ---------------------------------------------------------------------
    // find_oci_image_manifests_without_kind PG SQL pin
    // ---------------------------------------------------------------------

    /// Seed an `artifact_metadata` row carrying `oci_media_type` in its
    /// JSONB `metadata` column, for the media-type-discrimination tests
    /// below. Mirrors the shape `hort-http-oci`'s manifest write path
    /// stores it in.
    async fn seed_oci_media_type(pool: &PgPool, artifact_id: Uuid, media_type: &str) {
        sqlx::query(
            r#"INSERT INTO artifact_metadata (artifact_id, format, metadata)
               VALUES ($1, 'oci', jsonb_build_object('oci_media_type', $2::text))"#,
        )
        .bind(artifact_id)
        .bind(media_type)
        .execute(pool)
        .await
        .expect("seed artifact_metadata oci_media_type");
    }

    /// Insert an `oci_config` ContentReference row pointing the given
    /// source artifact at an arbitrary content hash — models "this
    /// manifest has already been repaired."
    async fn seed_oci_config_ref(
        pool: &PgPool,
        repo_id: Uuid,
        source_artifact_id: Uuid,
        seed: usize,
    ) {
        let target_hash = deterministic_hex64(seed ^ 0xFACE_FEED_usize);
        sqlx::query(
            r#"INSERT INTO content_references (
                   repository_id, source_artifact_id, target_content_hash,
                   kind, metadata, recorded_at
               ) VALUES (
                   $1, $2, $3, 'oci_config', '{}'::jsonb, now()
               )"#,
        )
        .bind(repo_id)
        .bind(source_artifact_id)
        .bind(&target_hash)
        .execute(pool)
        .await
        .expect("seed oci_config content_reference");
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_oci_image_manifests_without_kind_returns_empty_when_no_manifests_exist() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let r = PgArtifactRepository::new(pool.clone());
        let got = r
            .find_oci_image_manifests_without_kind("oci_config", 100)
            .await
            .expect("query");
        assert!(got.is_empty(), "no manifests seeded → empty candidate set");
        cleanup_repo(&pool, repo).await;
    }

    /// Mixed seed: an un-backfilled image manifest (candidate), a manifest
    /// that already has an `oci_config` row (NOT a candidate — NOT EXISTS
    /// prunes it), and a blob row under `blobs/sha256:…` (path filter
    /// excludes it regardless of content_references). The query MUST
    /// return exactly the one un-backfilled image manifest.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_oci_image_manifests_without_kind_excludes_repaired_and_blobs() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        let candidate = seed_artifact_at_path(
            &pool,
            repo,
            "manifests/sha256:aaaa000000000000000000000000000000000000000000000000000000000000",
            400,
        )
        .await;
        seed_oci_media_type(
            &pool,
            candidate,
            "application/vnd.oci.image.manifest.v1+json",
        )
        .await;

        let repaired = seed_artifact_at_path(
            &pool,
            repo,
            "manifests/sha256:bbbb000000000000000000000000000000000000000000000000000000000000",
            401,
        )
        .await;
        seed_oci_media_type(
            &pool,
            repaired,
            "application/vnd.oci.image.manifest.v1+json",
        )
        .await;
        seed_oci_config_ref(&pool, repo, repaired, 401).await;

        let _blob = seed_artifact_at_path(
            &pool,
            repo,
            "blobs/sha256:cccc000000000000000000000000000000000000000000000000000000000000",
            402,
        )
        .await;

        let r = PgArtifactRepository::new(pool.clone());
        let got = r
            .find_oci_image_manifests_without_kind("oci_config", 100)
            .await
            .expect("query");
        let got_ids: std::collections::HashSet<Uuid> = got.iter().map(|a| a.id).collect();
        assert_eq!(
            got_ids,
            [candidate].into_iter().collect(),
            "candidate set MUST be exactly the un-repaired image manifest: {got_ids:?}"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// An image index (`oci_media_type` = the index or manifest-list
    /// media type) MUST NEVER be returned — it legitimately has no
    /// `config`/`layers` edges (it carries `oci_index_member` children
    /// instead), so it would otherwise always match NOT EXISTS
    /// `oci_config` despite having nothing to repair.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_oci_image_manifests_without_kind_excludes_indexes() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        let index_artifact = seed_artifact_at_path(
            &pool,
            repo,
            "manifests/sha256:dddd000000000000000000000000000000000000000000000000000000000000",
            410,
        )
        .await;
        seed_oci_media_type(
            &pool,
            index_artifact,
            hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE,
        )
        .await;

        let docker_list_artifact = seed_artifact_at_path(
            &pool,
            repo,
            "manifests/sha256:eeee000000000000000000000000000000000000000000000000000000000000",
            411,
        )
        .await;
        seed_oci_media_type(
            &pool,
            docker_list_artifact,
            hort_domain::oci::DOCKER_MANIFEST_LIST_MEDIA_TYPE,
        )
        .await;

        let r = PgArtifactRepository::new(pool.clone());
        let got = r
            .find_oci_image_manifests_without_kind("oci_config", 100)
            .await
            .expect("query");
        assert!(
            got.is_empty(),
            "both index-shaped manifests must be excluded, got {got:?}"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// A manifest row with NO `artifact_metadata` row at all (the
    /// pre-metadata-migration shape this backfill exists for) is treated
    /// as an image manifest — mirroring `resolve_media_type`'s own
    /// fallback to the single-image default — and MUST be returned.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_oci_image_manifests_without_kind_includes_rows_with_no_metadata_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        let legacy = seed_artifact_at_path(
            &pool,
            repo,
            "manifests/sha256:ffff000000000000000000000000000000000000000000000000000000000000",
            420,
        )
        .await;
        // Deliberately no `seed_oci_media_type` call — models a row that
        // predates the metadata-write path entirely.

        let r = PgArtifactRepository::new(pool.clone());
        let got = r
            .find_oci_image_manifests_without_kind("oci_config", 100)
            .await
            .expect("query");
        let got_ids: std::collections::HashSet<Uuid> = got.iter().map(|a| a.id).collect();
        assert_eq!(
            got_ids,
            [legacy].into_iter().collect(),
            "a manifest with no artifact_metadata row must be treated as an image manifest"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// `limit` is honoured — mirrors `find_pypi_wheels_without_kind_honours_limit`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_oci_image_manifests_without_kind_honours_limit() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        for seed in 430..435 {
            let hex = deterministic_hex64(seed);
            let _ =
                seed_artifact_at_path(&pool, repo, &format!("manifests/sha256:{hex}"), seed).await;
        }

        let r = PgArtifactRepository::new(pool.clone());
        let got = r
            .find_oci_image_manifests_without_kind("oci_config", 3)
            .await
            .expect("query");
        assert_eq!(got.len(), 3, "LIMIT 3 must yield exactly 3 candidates");

        cleanup_repo(&pool, repo).await;
    }

    /// Soft-deleted manifests are excluded — mirrors
    /// `find_pypi_wheels_without_kind_excludes_soft_deleted_wheels`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_oci_image_manifests_without_kind_excludes_soft_deleted() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        let live_hex = deterministic_hex64(440);
        let live =
            seed_artifact_at_path(&pool, repo, &format!("manifests/sha256:{live_hex}"), 440).await;
        let dead_hex = deterministic_hex64(441);
        let deleted =
            seed_artifact_at_path(&pool, repo, &format!("manifests/sha256:{dead_hex}"), 441).await;
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(deleted)
            .execute(&pool)
            .await
            .expect("soft-delete update");

        let r = PgArtifactRepository::new(pool.clone());
        let got = r
            .find_oci_image_manifests_without_kind("oci_config", 100)
            .await
            .expect("query");
        let got_ids: std::collections::HashSet<Uuid> = got.iter().map(|a| a.id).collect();
        assert_eq!(
            got_ids,
            [live].into_iter().collect(),
            "soft-deleted manifest MUST be excluded — got {got_ids:?}"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// The registration-collision probe folds `-`/`_` on BOTH
    /// sides (the probe key is pre-folded by `cargo_collision_key`; the
    /// stored name is folded in SQL via `replace(name, '_', '-')`), so a
    /// stored `foo-bar` is found by a would-be `foo_bar` publish's key and
    /// vice versa. A non-colliding key misses, and soft-deleted rows do not
    /// reserve a name.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_canonical_name_by_collision_key_folds_both_separators() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let r = PgArtifactRepository::new(pool.clone());

        // Stored HYPHEN form is found by the folded key.
        let repo1 = seed_repo(&pool).await;
        seed_artifacts_with_name(&pool, repo1, "foo-bar", 1).await;
        assert_eq!(
            r.find_canonical_name_by_collision_key(repo1, "foo-bar")
                .await
                .expect("probe"),
            Some("foo-bar".to_string()),
            "stored foo-bar is found by the foo_bar publish's folded key"
        );
        // A non-colliding key misses.
        assert_eq!(
            r.find_canonical_name_by_collision_key(repo1, "baz-qux")
                .await
                .expect("probe"),
            None,
            "a non-colliding key returns None"
        );
        cleanup_repo(&pool, repo1).await;

        // Stored UNDERSCORE form also folds to the key — the SQL `replace`
        // runs on the stored name, not only the probe key.
        let repo2 = seed_repo(&pool).await;
        seed_artifacts_with_name(&pool, repo2, "foo_bar", 1).await;
        assert_eq!(
            r.find_canonical_name_by_collision_key(repo2, "foo-bar")
                .await
                .expect("probe"),
            Some("foo_bar".to_string()),
            "a stored foo_bar folds to foo-bar and is found"
        );

        // Soft-deleted rows do not reserve the collision key.
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE repository_id = $1")
            .bind(repo2)
            .execute(&pool)
            .await
            .expect("soft-delete update");
        assert_eq!(
            r.find_canonical_name_by_collision_key(repo2, "foo-bar")
                .await
                .expect("probe"),
            None,
            "soft-deleted rows do not reserve the collision key"
        );
        cleanup_repo(&pool, repo2).await;
    }

    // ---------------------------------------------------------------------
    // list_active_for_policy — ADR 0041 Item 2 (tighten-direction population)
    // ---------------------------------------------------------------------

    /// Seed a non-archived **global** scan policy projection so
    /// `list_active_for_policy`'s shadowing rule resolves every
    /// repo not shadowed by a repo-scoped policy. Returns the policy id.
    async fn seed_global_policy(pool: &PgPool) -> Uuid {
        let policy_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO policy_projections (
                   policy_id, name, scope, severity_threshold,
                   quarantine_duration_secs, require_approval, stream_version
               ) VALUES (
                   $1, $2, '"Global"'::jsonb, 'high',
                   86400, true, 0
               )"#,
        )
        .bind(policy_id)
        .bind(format!("it-active-policy-{}", policy_id.simple()))
        .execute(pool)
        .await
        .expect("seed global policy projection");
        policy_id
    }

    async fn cleanup_policy(pool: &PgPool, policy_id: Uuid) {
        let _ = sqlx::query("DELETE FROM policy_projections WHERE policy_id = $1")
            .bind(policy_id)
            .execute(pool)
            .await;
    }

    /// Bulk-insert N active artifacts under one repo with the given
    /// `quarantine_status`. Distinct version/path/checksum per row.
    async fn seed_status_artifacts(
        pool: &PgPool,
        repo: Uuid,
        status: &str,
        n: usize,
        seed_base: usize,
    ) {
        for i in 0..n {
            let id = Uuid::new_v4();
            let path = format!("simple/{status}/{status}-{i:08}.tar.gz");
            let sha256 = deterministic_hex64(seed_base + i);
            sqlx::query(
                r#"INSERT INTO artifacts (
                       id, repository_id, name, name_as_published, version, path,
                       size_bytes, checksum_sha256, content_type, storage_key,
                       quarantine_status
                   ) VALUES (
                       $1, $2, $3, $3, $4, $5,
                       0, $6, 'application/octet-stream', $6,
                       $7
                   )"#,
            )
            .bind(id)
            .bind(repo)
            .bind(format!("active-{status}"))
            .bind(format!("{i:08}"))
            .bind(&path)
            .bind(&sha256)
            .bind(status)
            .execute(pool)
            .await
            .expect("seed status artifact");
        }
    }

    /// `list_active_for_policy` returns ONLY the `Quarantined` / `Released`
    /// rows of a repo whose active policy resolves to `policy_id`,
    /// excludes `Rejected` / `ScanIndeterminate` / soft-deleted, paginates
    /// via `PageRequest`, and reports the full in-scope `total`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_active_for_policy_filters_status_and_paginates() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let policy_id = seed_global_policy(&pool).await;

        // In-scope active rows: 30 released + 20 quarantined = 50.
        seed_status_artifacts(&pool, repo_id, "released", 30, 0).await;
        seed_status_artifacts(&pool, repo_id, "quarantined", 20, 1_000).await;
        // Excluded rows: rejected + scan_indeterminate (not active).
        seed_status_artifacts(&pool, repo_id, "rejected", 5, 2_000).await;
        seed_status_artifacts(&pool, repo_id, "scan_indeterminate", 5, 3_000).await;
        // Excluded: soft-deleted released row.
        seed_artifact_status(
            &pool,
            repo_id,
            "active-released",
            Some("99.0.0"),
            Some("released"),
            true,
            4_000,
        )
        .await;

        let r = PgArtifactRepository::new(pool.clone());

        // First page of 20 — total reflects the full in-scope set (50).
        let page0 = r
            .list_active_for_policy(policy_id, PageRequest::new(0, 20))
            .await
            .expect("list_active_for_policy page0");
        assert_eq!(page0.items.len(), 20, "page size honoured");
        assert_eq!(page0.total, 50, "total reflects every in-scope active row");
        for a in &page0.items {
            assert!(
                matches!(
                    a.quarantine_status,
                    QuarantineStatus::Quarantined | QuarantineStatus::Released
                ),
                "only active statuses returned, got {:?}",
                a.quarantine_status
            );
        }

        // Walk every page (offset += page size); cumulative count == 50,
        // no duplicates — proves the uncapped page walk covers the whole
        // population with a stable `ORDER BY id`.
        let mut seen: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
        let mut offset: u64 = 0;
        let limit: u64 = 20;
        loop {
            let page = r
                .list_active_for_policy(policy_id, PageRequest::new(offset, limit))
                .await
                .expect("page");
            if page.items.is_empty() {
                break;
            }
            for a in &page.items {
                assert!(seen.insert(a.id), "no duplicate across pages: {}", a.id);
            }
            if (page.items.len() as u64) < limit {
                break;
            }
            offset += page.items.len() as u64;
        }
        assert_eq!(seen.len(), 50, "every in-scope active row visited once");

        cleanup_repo(&pool, repo_id).await;
        cleanup_policy(&pool, policy_id).await;
    }

    /// A repo-scoped policy SHADOWS the global one: `list_active_for_policy`
    /// for the global policy must NOT return active artifacts in a repo
    /// owned by a non-archived repo-scoped policy (mirrors
    /// `list_rejected_for_policy`'s precedence rule).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_active_for_policy_global_excludes_repo_shadowed_by_scoped_policy() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let global_policy = seed_global_policy(&pool).await;
        let shadowed_repo = seed_repo(&pool).await;
        let plain_repo = seed_repo(&pool).await;

        // A repo-scoped policy over `shadowed_repo` shadows the global one.
        let scoped_policy = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO policy_projections (
                   policy_id, name, scope, severity_threshold,
                   quarantine_duration_secs, require_approval, stream_version
               ) VALUES (
                   $1, $2, jsonb_build_object('Repository', $3::text), 'high',
                   86400, true, 0
               )"#,
        )
        .bind(scoped_policy)
        .bind(format!("it-scoped-{}", scoped_policy.simple()))
        .bind(shadowed_repo.to_string())
        .execute(&pool)
        .await
        .expect("seed repo-scoped policy");

        seed_status_artifacts(&pool, shadowed_repo, "released", 3, 5_000).await;
        seed_status_artifacts(&pool, plain_repo, "released", 4, 6_000).await;

        let r = PgArtifactRepository::new(pool.clone());
        let page = r
            .list_active_for_policy(global_policy, PageRequest::new(0, 100))
            .await
            .expect("list");
        // Only the un-shadowed repo's 4 active rows resolve to the global.
        assert_eq!(page.total, 4, "shadowed repo's rows excluded from global");
        for a in &page.items {
            assert_eq!(
                a.repository_id, plain_repo,
                "only un-shadowed repo rows returned"
            );
        }

        cleanup_repo(&pool, shadowed_repo).await;
        cleanup_repo(&pool, plain_repo).await;
        cleanup_policy(&pool, global_policy).await;
        cleanup_policy(&pool, scoped_policy).await;
    }

    // -----------------------------------------------------------------
    // `first_seen_for_checksum` — the live content-level age evidence
    // behind the quarantine anchor (ADR 0054).
    // -----------------------------------------------------------------

    /// Seed one artifact row carrying an explicit observation instant.
    /// `created_at` is written explicitly (rather than left to the
    /// column default) precisely because it IS the value under test.
    async fn seed_observation(
        pool: &PgPool,
        repo: Uuid,
        sha256: &str,
        created_at: DateTime<Utc>,
        is_deleted: bool,
    ) {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   is_deleted, created_at
               ) VALUES (
                   $1, $2, 'obs-pkg', 'obs-pkg', '1.0.0', $3,
                   0, $4, 'application/octet-stream', $4,
                   $5, $6
               )"#,
        )
        .bind(id)
        .bind(repo)
        .bind(format!("obs-pkg/1.0.0/{id}.tar.gz"))
        .bind(sha256)
        .bind(is_deleted)
        .bind(created_at)
        .execute(pool)
        .await
        .expect("seed observation row");
    }

    /// No row carries the hash ⇒ `None`. The aggregate returns one row
    /// holding SQL NULL, so this pins that the adapter maps that to
    /// "no evidence" rather than erroring on a missing row — the caller
    /// reads `None` as "fall back on the mint instant".
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn first_seen_for_checksum_reports_no_evidence_for_an_unknown_hash() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let r = PgArtifactRepository::new(pool.clone());
        let unknown: ContentHash = deterministic_hex64(0xF145_7BAD).parse().unwrap();

        let seen = r
            .first_seen_for_checksum(&unknown)
            .await
            .expect("aggregate read");

        assert_eq!(seen, None, "unknown hash has no observation");
    }

    /// The evidence is the minimum over EVERY repository's rows for that
    /// hash — the property that dissolves the leader/follower asymmetry:
    /// whichever repository observed the content first supplies the age
    /// fact for all of them. Rows carrying a different hash must not
    /// contribute, however early they are.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn first_seen_for_checksum_is_the_minimum_across_repositories() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_a = seed_repo(&pool).await;
        let repo_b = seed_repo(&pool).await;
        let subject = deterministic_hex64(0x0B5E_4ED0);
        let other = deterministic_hex64(0x07E4_0000);

        let earliest: DateTime<Utc> = "2025-01-02T03:04:05Z".parse().unwrap();
        let later: DateTime<Utc> = "2026-07-08T09:10:11Z".parse().unwrap();
        let decoy: DateTime<Utc> = "2020-01-01T00:00:00Z".parse().unwrap();

        seed_observation(&pool, repo_b, &subject, later, false).await;
        seed_observation(&pool, repo_a, &subject, earliest, false).await;
        // A far earlier row for DIFFERENT content — must not leak in.
        seed_observation(&pool, repo_a, &other, decoy, false).await;

        let r = PgArtifactRepository::new(pool.clone());
        let seen = r
            .first_seen_for_checksum(&subject.parse().unwrap())
            .await
            .expect("aggregate read");

        assert_eq!(
            seen,
            Some(earliest),
            "the earliest observation of THIS hash, in any repository"
        );

        cleanup_repo(&pool, repo_a).await;
        cleanup_repo(&pool, repo_b).await;
    }

    /// A soft-deleted row still counts. Withdrawing a row from service
    /// does not un-observe the bytes, and the observation is exactly what
    /// this read reports — only a hard purge (which removes the row)
    /// retires the evidence. This is the one place the port deviates from
    /// the `is_deleted = false` filter the rest of the read path applies,
    /// so it is pinned rather than left to the SQL's shape.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn first_seen_for_checksum_counts_soft_deleted_observations() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let subject = deterministic_hex64(0x50F7_DEAD);

        let soft_deleted_at: DateTime<Utc> = "2024-03-04T05:06:07Z".parse().unwrap();
        let live_at: DateTime<Utc> = "2026-03-04T05:06:07Z".parse().unwrap();
        seed_observation(&pool, repo_id, &subject, soft_deleted_at, true).await;
        seed_observation(&pool, repo_id, &subject, live_at, false).await;

        let r = PgArtifactRepository::new(pool.clone());
        let seen = r
            .first_seen_for_checksum(&subject.parse().unwrap())
            .await
            .expect("aggregate read");

        assert_eq!(
            seen,
            Some(soft_deleted_at),
            "a soft-deleted row is a withdrawn service row, not a retracted observation"
        );

        cleanup_repo(&pool, repo_id).await;
    }
}
