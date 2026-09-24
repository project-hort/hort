//! PostgreSQL adapter for [`RetentionCandidateReader`] (ADR 0020).
//!
//! Enumerates non-protected artifacts and resolves each one's
//! repo-scoped rescan interval (freshness-window input)
//! via the repo→policy chain — the **identical**
//! `JOIN LATERAL policy_projections` the
//! [`rescan_candidates`](crate::rescan_candidates) adapter uses, with
//! two deliberate deviations from the rescan adapter:
//!
//! 1. **LEFT** join, not INNER: an artifact with no resolved scan
//!    policy yields `resolved_rescan_interval_hours = None` (→ default
//!    24 h) rather than being dropped — age-based retention applies
//!    even without a scan policy.
//! 2. The protected-status filter admits SQL `NULL`, `none`, the legacy
//!    non-terminal scan spellings (`unscanned`, `clean`, `flagged`), and
//!    `released`; it excludes exactly `quarantined`, `rejected`, and
//!    `scan_indeterminate`. This is broader than the rescan adapter's
//!    `= 'released'`. Soft-deleted artifacts are outside the enumeration.
//!
//! The query additionally `JOIN`s `repositories r ON r.id =
//! a.repository_id` to select `r.format::text` (aliased `repo_format`) — the
//! required enum-to-text cast lets sqlx decode the per-artifact
//! [`RepositoryFormat`] the `RetentionScope::Format`
//! gate needs (`Artifact` itself has no `format` field). This is an
//! INNER join: every artifact's `repository_id` is a FK into
//! `repositories`, so it never drops a row. Still a **single query**:
//! no extra round-trip, no N+1, no scope SQL pre-filter (scope
//! matching stays in `RetentionUseCase::evaluate_one` per the port
//! docstring).
//!
//! Keyset-paginated by `artifacts.id` (`after` cursor + `ORDER BY a.id
//! LIMIT $batch`): retention has no in-flight-job dedup to naturally
//! bound re-visits, so the handler advances the cursor across pages
//! (the daily cron drains any backlog, identical posture to
//! cron-rescan's single-shot cap).
//!
//! # `keep_rank` / `sibling_total` — and why the page is a CTE
//!
//! The `KeepLastN` input is resolved in this same statement by a
//! window function over `(repository_id, name)`, ordered newest-first
//! by `created_at` with `id DESC` as the deterministic tiebreak (the
//! ordering is the retention contract — see the port docs).
//!
//! A window function is evaluated **after** `WHERE` and **before**
//! `LIMIT`, so writing `ROW_NUMBER() OVER (…)` straight into the
//! paginated query would rank each artifact within the slice of its
//! sibling group that survived the keyset cursor and the
//! protected-status filter — a rank that shifts with the page
//! boundary and with quarantine state, expiring the wrong artifacts.
//! A sibling group can be several times the 1000-row page, so this is
//! the common case, not a corner.
//!
//! The query therefore picks the page first (`page`, materialised so
//! the `ORDER BY … LIMIT` is evaluated exactly once), collects the
//! distinct `(repository_id, name)` groups it touched, and ranks over
//! **every live row** of those groups (`ranked`) before joining the
//! rank back onto the page. Consequences, all intended:
//!
//! - The live set is `deleted_at IS NULL` — the same definition this
//!   adapter's own enumeration uses. A retired sibling occupies no
//!   rank slot, so it cannot shield itself and push an extra live
//!   artifact over the edge.
//! - GC-protected siblings (`quarantined` / `rejected` /
//!   `scan_indeterminate`) are absent from `page` but present in
//!   `ranked`: they are live bytes on disk, and "keep the last n"
//!   counts live artifacts.
//! - Ranking is bounded by the groups the page actually touched
//!   rather than by the whole table.
//!
//! # `tag_targeted` — the `KeepLastN` tag exemption
//!
//! An `EXISTS` over `mutable_refs`, repository-scoped, covering both
//! target kinds: `target_kind = 'hash'` against `checksum_sha256` (the
//! OCI tag, which resolves a tag to a content hash) and
//! `target_kind = 'version'` against `(namespace, version)` (the npm
//! dist-tag and every other non-OCI mutable pointer, whose namespace
//! is the package name the artifact is stored under).
//!
//! Both halves are load-bearing. Dropping the repository scope would
//! exempt an untagged artifact because identical bytes are tagged in
//! another repository — content hashes are shared across repositories
//! by construction. Dropping the version kind would silently protect
//! nothing outside OCI. And the `namespace = a.name` conjunct on the
//! version arm is what keeps one package's `latest` from exempting
//! every other package that happens to share that version string.
//!
//! Both arms are backed by the repository-scoped partial indexes on
//! `mutable_refs` (`(repository_id, target_hash)` and
//! `(repository_id, target_version)`).

use chrono::{DateTime, Utc};
use sqlx::{postgres::PgRow, FromRow, PgPool, Row};
use uuid::Uuid;

use hort_domain::entities::artifact::Artifact;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::retention_candidate_reader::{
    RetentionCandidateReader, RetentionCandidateRow,
};

use crate::mappers::ArtifactRow;
use crate::{gc_protected_quarantine_status_names, map_sqlx_error, BoxFuture};

/// PostgreSQL adapter for the retention candidate-enumeration query.
pub struct PgRetentionCandidateReader {
    pool: PgPool,
}

impl PgRetentionCandidateReader {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn decode_candidate(row: &PgRow) -> DomainResult<RetentionCandidateRow> {
    // `ArtifactRow` is `FromRow`; it reads only its own named columns
    // from the wider joined result set.
    let ar = ArtifactRow::from_row(row).map_err(|e| {
        tracing::warn!(error = %e, "retention_candidate artifact row decode failed");
        DomainError::Invariant(format!("retention_candidate artifact row decode: {e}"))
    })?;
    let artifact = Artifact::try_from(ar)?;
    // `repositories.format::text` → `RepositoryFormat`. The cast in the
    // query is load-bearing: sqlx will not decode the `repository_format`
    // enum into `String`, and without it every non-empty page fails on its
    // first row. The parse itself is infallible — an unrecognised name folds
    // to `RepositoryFormat::Other(name)` — which is the same mapping idiom
    // the `RepositoryRow` → `Repository` mapper uses (`mappers.rs`:
    // `.parse().unwrap_or(RepositoryFormat::Generic)`).
    let repo_format_raw: String = row.try_get("repo_format").map_err(|e| {
        tracing::warn!(error = %e, "retention_candidate repo format decode failed");
        DomainError::Invariant(format!("retention_candidate repo_format decode: {e}"))
    })?;
    let format: RepositoryFormat = repo_format_raw.parse().unwrap_or(RepositoryFormat::Generic);
    let resolved_rescan_interval_hours: Option<i32> =
        row.try_get("resolved_rescan_interval_hours").map_err(|e| {
            tracing::warn!(error = %e, "retention_candidate rescan-interval decode failed");
            DomainError::Invariant(format!(
                "retention_candidate resolved_rescan_interval_hours decode: {e}"
            ))
        })?;
    // `ROW_NUMBER()` / `COUNT(*)` are `bigint`. A sibling group that
    // overflowed `u32` is not reachable in this schema, but the
    // conversion is still fallible, and the fallible direction is the
    // safe one: `None` makes the pure evaluator fail `KeepLastN` shut
    // rather than act on a truncated rank.
    let rank_raw: i64 = row.try_get("keep_rank").map_err(|e| {
        tracing::warn!(error = %e, "retention_candidate keep_rank decode failed");
        DomainError::Invariant(format!("retention_candidate keep_rank decode: {e}"))
    })?;
    let total_raw: i64 = row.try_get("sibling_total").map_err(|e| {
        tracing::warn!(error = %e, "retention_candidate sibling_total decode failed");
        DomainError::Invariant(format!("retention_candidate sibling_total decode: {e}"))
    })?;
    let keep_rank = match (u32::try_from(rank_raw), u32::try_from(total_raw)) {
        (Ok(rank), Ok(total)) => Some((rank, total)),
        _ => {
            tracing::warn!(
                artifact_id = %artifact.id,
                rank_raw,
                total_raw,
                "retention_candidate sibling ranking does not fit u32 — \
                 reported as unresolved so KeepLastN fails safe"
            );
            None
        }
    };
    let tag_targeted: bool = row.try_get("tag_targeted").map_err(|e| {
        tracing::warn!(error = %e, "retention_candidate tag_targeted decode failed");
        DomainError::Invariant(format!("retention_candidate tag_targeted decode: {e}"))
    })?;
    Ok(RetentionCandidateRow {
        artifact,
        format,
        resolved_rescan_interval_hours: resolved_rescan_interval_hours.map(i64::from),
        keep_rank,
        tag_targeted,
    })
}

impl RetentionCandidateReader for PgRetentionCandidateReader {
    fn list_candidates<'a>(
        &'a self,
        batch_size: u32,
        after: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<Vec<RetentionCandidateRow>>> {
        Box::pin(async move {
            tracing::debug!(
                entity = "retention_candidate",
                batch_size,
                has_cursor = after.is_some(),
                %now,
                "list_candidates"
            );
            // The LATERAL picks the resolved policy per artifact: a
            // repo-scoped non-archived policy if one exists, else a
            // non-archived Global. LEFT JOIN so a no-policy artifact
            // is kept with `resolved_rescan_interval_hours = NULL`
            // (→ default 24h) — NOT dropped (the rescan adapter's
            // INNER-join behaviour is wrong for age-based retention).
            //
            // `$3::uuid` keyset cursor: when NULL, no lower bound
            // (first page); otherwise `a.id > $3`. The `now`
            // parameter is bound for caller-pinned time coherence
            // even though the protected-status filter does not
            // consult it — kept in the signature/SQL so a future age
            // pre-filter has a pinned `now` available without a
            // signature change.
            let sql = format!(
                r#"
                WITH page AS MATERIALIZED (
                    SELECT a.id
                    FROM artifacts a
                    WHERE (a.quarantine_status IS NULL
                           OR a.quarantine_status <> ALL($4::text[]))
                      AND a.deleted_at IS NULL
                      AND ($3::uuid IS NULL OR a.id > $3)
                    ORDER BY a.id
                    LIMIT $1
                ),
                sibling_groups AS (
                    SELECT DISTINCT a.repository_id, a.name
                    FROM artifacts a
                    JOIN page pg ON pg.id = a.id
                ),
                ranked AS (
                    SELECT s.id,
                           ROW_NUMBER() OVER (
                               PARTITION BY s.repository_id, s.name
                               ORDER BY s.created_at DESC, s.id DESC
                           ) AS keep_rank,
                           COUNT(*) OVER (
                               PARTITION BY s.repository_id, s.name
                           ) AS sibling_total
                    FROM artifacts s
                    JOIN sibling_groups g
                      ON g.repository_id = s.repository_id
                     AND g.name = s.name
                    WHERE s.deleted_at IS NULL
                )
                SELECT a.id, a.repository_id, a.name, a.name_as_published,
                       a.version, a.path, a.size_bytes,
                       a.checksum_sha256, a.checksum_sha1, a.checksum_md5,
                       a.content_type, a.storage_key,
                       a.quarantine_status, a.quarantine_window_start,
                       a.upstream_published_at,
                       a.uploaded_by,
                       a.created_at, a.updated_at, a.deleted_at,
                       r.format::text AS repo_format,
                       p.rescan_interval_hours AS resolved_rescan_interval_hours,
                       rk.keep_rank AS keep_rank,
                       rk.sibling_total AS sibling_total,
                       {tag_targeted} AS tag_targeted
                FROM page pg
                JOIN artifacts a ON a.id = pg.id
                JOIN ranked rk ON rk.id = a.id
                JOIN repositories r ON r.id = a.repository_id
                LEFT JOIN LATERAL (
                    SELECT pp.rescan_interval_hours
                    FROM policy_projections pp
                    WHERE pp.archived = false
                      AND (
                            (pp.scope ? 'Repository'
                              AND (pp.scope->>'Repository')::uuid = a.repository_id)
                         OR (pp.scope ? 'Global'
                              AND NOT EXISTS (
                                SELECT 1 FROM policy_projections pp2
                                WHERE pp2.archived = false
                                  AND pp2.scope ? 'Repository'
                                  AND (pp2.scope->>'Repository')::uuid = a.repository_id
                              ))
                          )
                    ORDER BY (pp.scope ? 'Repository') DESC
                    LIMIT 1
                ) p ON TRUE
                ORDER BY a.id
            "#,
                tag_targeted = crate::ARTIFACT_IS_TAG_TARGETED_SQL,
            );
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(i64::from(batch_size))
                .bind(now)
                .bind(after)
                .bind(gc_protected_quarantine_status_names())
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "RetentionCandidate", "list_candidates"))?;
            rows.iter().map(decode_candidate).collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::entities::artifact::QuarantineStatus;
    use serial_test::serial;
    use std::collections::{HashMap, HashSet};
    use std::env;

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;
        Some(pool)
    }

    async fn seed_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("it-retention-candidate-{}", id.simple());
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
        repo_id: Uuid,
        quarantine_status: Option<&str>,
        deleted: bool,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let name = format!("candidate-{}", id.simple());
        let path = format!("artifacts/{name}");
        sqlx::query(
            r#"INSERT INTO artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   quarantine_status, deleted_at
               ) VALUES (
                   $1, $2, $3, $3, '1.0.0', $4,
                   0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                   'application/octet-stream', $4, $5,
                   CASE WHEN $6 THEN now() ELSE NULL END
               )"#,
        )
        .bind(id)
        .bind(repo_id)
        .bind(name)
        .bind(path)
        .bind(quarantine_status)
        .bind(deleted)
        .execute(pool)
        .await
        .expect("seed artifact");
        id
    }

    /// Seed one artifact with full control over the fields the ranking
    /// and the tag exemption read.
    #[allow(clippy::too_many_arguments)]
    async fn seed_sibling(
        pool: &PgPool,
        repo_id: Uuid,
        name: &str,
        version: &str,
        created_at: DateTime<Utc>,
        checksum: &str,
        quarantine_status: Option<&str>,
        deleted: bool,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let path = format!("{name}/{version}/{}", id.simple());
        sqlx::query(
            r#"INSERT INTO artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   quarantine_status, created_at, deleted_at
               ) VALUES (
                   $1, $2, $3, $3, $4, $5,
                   0, $6, 'application/octet-stream', $5, $7, $8,
                   CASE WHEN $9 THEN now() ELSE NULL END
               )"#,
        )
        .bind(id)
        .bind(repo_id)
        .bind(name)
        .bind(version)
        .bind(&path)
        .bind(checksum)
        .bind(quarantine_status)
        .bind(created_at)
        .bind(deleted)
        .execute(pool)
        .await
        .expect("seed sibling");
        id
    }

    /// A deterministic 64-hex content hash for fixture `n`.
    fn fixture_hash(n: u8) -> String {
        format!("{:0>64}", format!("{n:x}"))
    }

    async fn seed_ref_to_hash(pool: &PgPool, repo_id: Uuid, namespace: &str, hash: &str) {
        sqlx::query(
            r#"INSERT INTO mutable_refs (
                   repository_id, namespace, ref_name, target_kind, target_hash
               ) VALUES ($1, $2, 'tag-hash', 'hash', $3)"#,
        )
        .bind(repo_id)
        .bind(namespace)
        .bind(hash)
        .execute(pool)
        .await
        .expect("seed hash ref");
    }

    async fn seed_ref_to_version(pool: &PgPool, repo_id: Uuid, namespace: &str, version: &str) {
        sqlx::query(
            r#"INSERT INTO mutable_refs (
                   repository_id, namespace, ref_name, target_kind, target_version
               ) VALUES ($1, $2, 'tag-version', 'version', $3)"#,
        )
        .bind(repo_id)
        .bind(namespace)
        .bind(version)
        .execute(pool)
        .await
        .expect("seed version ref");
    }

    /// Every candidate the reader yields, keyed by artifact id.
    async fn candidates_by_id(pool: &PgPool, batch: u32) -> HashMap<Uuid, RetentionCandidateRow> {
        let reader = PgRetentionCandidateReader::new(pool.clone());
        let mut out = HashMap::new();
        let mut cursor: Option<Uuid> = None;
        loop {
            let page = reader
                .list_candidates(batch, cursor, Utc::now())
                .await
                .expect("list candidates");
            if page.is_empty() {
                break;
            }
            cursor = page.last().map(|r| r.artifact.id);
            let short = (page.len() as u32) < batch;
            for row in page {
                out.insert(row.artifact.id, row);
            }
            if short {
                break;
            }
        }
        out
    }

    fn rank_of(rows: &HashMap<Uuid, RetentionCandidateRow>, id: Uuid) -> (u32, u32) {
        rows.get(&id)
            .unwrap_or_else(|| panic!("{id} is not a candidate"))
            .keep_rank
            .expect("a live artifact always ranks")
    }

    async fn candidate_ids(pool: PgPool) -> HashSet<Uuid> {
        PgRetentionCandidateReader::new(pool)
            .list_candidates(1000, None, Utc::now())
            .await
            .expect("list candidates")
            .into_iter()
            .map(|candidate| candidate.artifact.id)
            .collect()
    }

    /// Empty-table query compiles + runs (also exercises the keyset
    /// cursor binding path).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_candidates_empty_db_returns_empty() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let reader = PgRetentionCandidateReader::new(pool);
        // No cursor.
        let none = reader
            .list_candidates(1000, None, Utc::now())
            .await
            .expect("query runs");
        // With a cursor (exercises the `$3 IS NOT NULL` branch).
        let after = reader
            .list_candidates(1000, Some(Uuid::new_v4()), Utc::now())
            .await
            .expect("query runs with cursor");
        // The shared test DB may contain rows from other suites; the
        // only invariant we can assert without seeding is that the
        // protected-status filter never yields a protected artifact.
        for c in none.iter().chain(after.iter()) {
            assert!(
                !matches!(
                    c.artifact.quarantine_status,
                    QuarantineStatus::Quarantined
                        | QuarantineStatus::Rejected
                        | QuarantineStatus::ScanIndeterminate
                ),
                "protected artifact leaked into retention candidates"
            );
        }
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_candidates_includes_null_and_legacy_non_terminal_statuses() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let null_status = seed_artifact(&pool, repo_id, None, false).await;
        let unscanned = seed_artifact(&pool, repo_id, Some("unscanned"), false).await;

        let ids = candidate_ids(pool).await;

        assert!(ids.contains(&null_status));
        assert!(ids.contains(&unscanned));
        // The other legacy non-terminal spellings, `clean` and `flagged`,
        // belong to the same eligible class and are covered by the full matrix below.
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_candidates_excludes_soft_deleted_and_protected_statuses() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let live = seed_artifact(&pool, repo_id, Some("released"), false).await;
        let deleted = seed_artifact(&pool, repo_id, Some("released"), true).await;
        let quarantined = seed_artifact(&pool, repo_id, Some("quarantined"), false).await;
        let rejected = seed_artifact(&pool, repo_id, Some("rejected"), false).await;
        let scan_indeterminate =
            seed_artifact(&pool, repo_id, Some("scan_indeterminate"), false).await;

        let ids = candidate_ids(pool).await;

        assert!(ids.contains(&live));
        assert!(!ids.contains(&deleted));
        assert!(!ids.contains(&quarantined));
        assert!(!ids.contains(&rejected));
        assert!(!ids.contains(&scan_indeterminate));
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn candidate_filter_and_purge_mapper_agree_for_every_persisted_status() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let mut seeded = Vec::new();
        for raw in [
            None,
            Some("unscanned"),
            Some("clean"),
            Some("flagged"),
            Some("quarantined"),
            Some("released"),
            Some("rejected"),
            Some("scan_indeterminate"),
        ] {
            let id = seed_artifact(&pool, repo_id, raw, false).await;
            seeded.push((id, raw));
        }

        let ids = candidate_ids(pool).await;
        for (id, raw) in seeded {
            let mapped = crate::purge_gc::map_status(raw).expect("schema status maps");
            let protected = matches!(
                mapped,
                QuarantineStatus::Quarantined
                    | QuarantineStatus::Rejected
                    | QuarantineStatus::ScanIndeterminate
            );
            assert_eq!(
                ids.contains(&id),
                !protected,
                "candidate SQL disagrees with purge mapper for {raw:?}"
            );
        }
    }

    // -- keep_rank ------------------------------------------------------

    /// The ordering contract: newest first by `created_at`, within
    /// `(repository_id, name)`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn keep_rank_orders_siblings_newest_first() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mut ids = Vec::new();
        for i in 0..4i64 {
            ids.push(
                seed_sibling(
                    &pool,
                    repo,
                    "pkg",
                    &format!("1.0.{i}"),
                    base + chrono::Duration::seconds(i),
                    &fixture_hash(u8::try_from(i).unwrap()),
                    Some("released"),
                    false,
                )
                .await,
            );
        }

        let rows = candidates_by_id(&pool, 1000).await;

        // ids[3] is the newest → rank 1; ids[0] the oldest → rank 4.
        assert_eq!(rank_of(&rows, ids[3]), (1, 4));
        assert_eq!(rank_of(&rows, ids[2]), (2, 4));
        assert_eq!(rank_of(&rows, ids[1]), (3, 4));
        assert_eq!(rank_of(&rows, ids[0]), (4, 4));
    }

    /// A different `name` in the same repository is a different
    /// sibling group and gets its own rank sequence.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn keep_rank_partitions_by_name_within_a_repository() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let a = seed_sibling(
            &pool,
            repo,
            "alpha",
            "1.0.0",
            base,
            &fixture_hash(1),
            Some("released"),
            false,
        )
        .await;
        let b = seed_sibling(
            &pool,
            repo,
            "beta",
            "1.0.0",
            base,
            &fixture_hash(2),
            Some("released"),
            false,
        )
        .await;

        let rows = candidates_by_id(&pool, 1000).await;

        assert_eq!(rank_of(&rows, a), (1, 1));
        assert_eq!(rank_of(&rows, b), (1, 1));
    }

    /// Two artifacts stored in the same instant must not be free to
    /// swap ranks between runs: the artifact id breaks the tie,
    /// descending, and it does so reproducibly.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn keep_rank_tiebreak_on_equal_created_at_is_id_descending() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let same_instant = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let a = seed_sibling(
            &pool,
            repo,
            "pkg",
            "1.0.0",
            same_instant,
            &fixture_hash(1),
            Some("released"),
            false,
        )
        .await;
        let b = seed_sibling(
            &pool,
            repo,
            "pkg",
            "1.0.1",
            same_instant,
            &fixture_hash(2),
            Some("released"),
            false,
        )
        .await;

        let (higher, lower) = if a > b { (a, b) } else { (b, a) };
        for attempt in 0..3 {
            let rows = candidates_by_id(&pool, 1000).await;
            assert_eq!(
                rank_of(&rows, higher),
                (1, 2),
                "attempt {attempt}: the greater id must win the tie"
            );
            assert_eq!(rank_of(&rows, lower), (2, 2), "attempt {attempt}");
        }
    }

    /// A retired sibling occupies no rank slot — otherwise it would
    /// shield itself and push one extra live artifact over the edge.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn keep_rank_excludes_soft_deleted_siblings() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        // The newest sibling is retired; it must not hold rank 1.
        seed_sibling(
            &pool,
            repo,
            "pkg",
            "2.0.0",
            base + chrono::Duration::seconds(100),
            &fixture_hash(9),
            Some("released"),
            true,
        )
        .await;
        let live_new = seed_sibling(
            &pool,
            repo,
            "pkg",
            "1.0.1",
            base + chrono::Duration::seconds(10),
            &fixture_hash(1),
            Some("released"),
            false,
        )
        .await;
        let live_old = seed_sibling(
            &pool,
            repo,
            "pkg",
            "1.0.0",
            base,
            &fixture_hash(2),
            Some("released"),
            false,
        )
        .await;

        let rows = candidates_by_id(&pool, 1000).await;

        assert_eq!(rank_of(&rows, live_new), (1, 2));
        assert_eq!(rank_of(&rows, live_old), (2, 2));
    }

    /// A GC-protected sibling is not enumerable as a candidate but it
    /// is live content on disk, so it still occupies a rank slot —
    /// "keep the last n" counts live artifacts.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn keep_rank_counts_gc_protected_siblings() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let quarantined = seed_sibling(
            &pool,
            repo,
            "pkg",
            "2.0.0",
            base + chrono::Duration::seconds(100),
            &fixture_hash(9),
            Some("quarantined"),
            false,
        )
        .await;
        let released = seed_sibling(
            &pool,
            repo,
            "pkg",
            "1.0.0",
            base,
            &fixture_hash(1),
            Some("released"),
            false,
        )
        .await;

        let rows = candidates_by_id(&pool, 1000).await;

        assert!(
            !rows.contains_key(&quarantined),
            "a protected artifact is not a candidate"
        );
        assert_eq!(
            rank_of(&rows, released),
            (2, 2),
            "the protected sibling still holds rank 1"
        );
    }

    /// The rank is a property of the sibling group, never of the page.
    /// A window function evaluated inside the keyset-filtered query
    /// would rank each artifact within the page slice instead; this
    /// pins the two runs to the identical ranking.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn keep_rank_is_stable_across_page_boundaries() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let group = 7usize;
        for i in 0..group {
            seed_sibling(
                &pool,
                repo,
                "pkg",
                &format!("1.0.{i}"),
                base + chrono::Duration::seconds(i as i64),
                &fixture_hash(u8::try_from(i).unwrap()),
                Some("released"),
                false,
            )
            .await;
        }

        let unpaginated = candidates_by_id(&pool, 1000).await;
        // A batch far smaller than the sibling group, so every page
        // boundary falls inside it.
        let paginated = candidates_by_id(&pool, 2).await;

        assert_eq!(unpaginated.len(), group);
        assert_eq!(paginated.len(), group);
        for (id, row) in &unpaginated {
            assert_eq!(
                paginated[id].keep_rank, row.keep_rank,
                "rank of {id} shifted with the page boundary"
            );
        }
        // And the ranking itself is the complete 1..=7 sequence.
        let mut ranks: Vec<u32> = paginated
            .values()
            .map(|r| r.keep_rank.expect("ranked").0)
            .collect();
        ranks.sort_unstable();
        assert_eq!(ranks, (1..=group as u32).collect::<Vec<_>>());
    }

    // -- tag_targeted ---------------------------------------------------

    /// The OCI shape: a tag pointing at a content hash.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn tag_targeted_covers_the_hash_target_kind() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let tagged_hash = fixture_hash(7);
        let tagged = seed_sibling(
            &pool,
            repo,
            "pkg",
            "1.0.0",
            base,
            &tagged_hash,
            Some("released"),
            false,
        )
        .await;
        let untagged = seed_sibling(
            &pool,
            repo,
            "pkg",
            "1.0.1",
            base,
            &fixture_hash(8),
            Some("released"),
            false,
        )
        .await;
        seed_ref_to_hash(&pool, repo, "pkg", &tagged_hash).await;

        let rows = candidates_by_id(&pool, 1000).await;

        assert!(rows[&tagged].tag_targeted);
        assert!(!rows[&untagged].tag_targeted);
    }

    /// The npm dist-tag shape: a pointer at a version string. A
    /// hash-only exemption fails this one, and the largest real
    /// repositories are not OCI.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn tag_targeted_covers_the_version_target_kind() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let tagged = seed_sibling(
            &pool,
            repo,
            "pkg",
            "1.0.0",
            base,
            &fixture_hash(1),
            Some("released"),
            false,
        )
        .await;
        let untagged = seed_sibling(
            &pool,
            repo,
            "pkg",
            "1.0.1",
            base,
            &fixture_hash(2),
            Some("released"),
            false,
        )
        .await;
        seed_ref_to_version(&pool, repo, "pkg", "1.0.0").await;

        let rows = candidates_by_id(&pool, 1000).await;

        assert!(rows[&tagged].tag_targeted);
        assert!(!rows[&untagged].tag_targeted);
    }

    /// A version pointer names `(namespace, version)`. Without the
    /// namespace conjunct one package's `latest` would exempt every
    /// other package that happens to share the version string.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn tag_targeted_version_kind_is_scoped_to_its_namespace() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let other_package = seed_sibling(
            &pool,
            repo,
            "beta",
            "1.0.0",
            base,
            &fixture_hash(2),
            Some("released"),
            false,
        )
        .await;
        // The ref belongs to `alpha`, at the same version string.
        seed_ref_to_version(&pool, repo, "alpha", "1.0.0").await;

        let rows = candidates_by_id(&pool, 1000).await;

        assert!(!rows[&other_package].tag_targeted);
    }

    /// Content hashes are shared across repositories by construction
    /// — that is what CAS is. A hash-global lookup would exempt the
    /// artifact next door because identical bytes are tagged here.
    /// Asserted through the real evaluator: the untagged twin expires.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn identical_content_tagged_in_another_repository_still_expires() {
        use hort_domain::retention::{matches_bool, EvaluationInputs, PolicyPredicate};

        let Some(pool) = maybe_pool().await else {
            return;
        };
        let tagged_repo = seed_repo(&pool).await;
        let other_repo = seed_repo(&pool).await;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let shared_hash = fixture_hash(5);

        // Each repository holds the same two versions of `pkg`; the
        // older one is byte-identical across both.
        let mut old = Vec::new();
        for repo in [tagged_repo, other_repo] {
            old.push(
                seed_sibling(
                    &pool,
                    repo,
                    "pkg",
                    "1.0.0",
                    base,
                    &shared_hash,
                    Some("released"),
                    false,
                )
                .await,
            );
            seed_sibling(
                &pool,
                repo,
                "pkg",
                "1.0.1",
                base + chrono::Duration::seconds(10),
                &fixture_hash(6),
                Some("released"),
                false,
            )
            .await;
        }
        let (here, next_door) = (old[0], old[1]);
        // Only `tagged_repo` tags it — by hash and by version, so
        // neither arm can be the one leaking.
        seed_ref_to_hash(&pool, tagged_repo, "pkg", &shared_hash).await;
        seed_ref_to_version(&pool, tagged_repo, "pkg", "1.0.0").await;

        let rows = candidates_by_id(&pool, 1000).await;
        assert!(rows[&here].tag_targeted);
        assert!(
            !rows[&next_door].tag_targeted,
            "the exemption must not leak across repositories through CAS"
        );

        // Both are rank 2 of 2. Under KeepLastN(1) the tagged one
        // survives and its untagged twin does not.
        let predicate = PolicyPredicate::KeepLastN(1);
        let now = Utc::now();
        let expires = |id: Uuid| {
            let row = &rows[&id];
            assert_eq!(row.keep_rank, Some((2, 2)));
            matches_bool(
                &predicate,
                &EvaluationInputs {
                    now,
                    created_at: row.artifact.created_at,
                    last_downloaded_at: None,
                    keep_rank: row.keep_rank,
                    tag_targeted: row.tag_targeted,
                    findings: &[],
                    first_detected_at: row.artifact.created_at,
                    latest_scan_at: row.artifact.created_at,
                },
            )
        };
        assert!(!expires(here), "the tag target in its own repo survives");
        assert!(
            expires(next_door),
            "identical content tagged elsewhere must still expire"
        );
    }

    // -- reader + evaluator, end to end ----------------------------------

    /// The headline behaviour: `KeepLastN(n)` leaves exactly the `n`
    /// newest versions of a `(repository, name)` group and marks the
    /// rest — except a tag target, which survives whatever its rank.
    /// Runs the real rows through the real pure evaluator.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn keep_last_n_marks_every_sibling_past_the_window_except_a_tag_target() {
        use hort_domain::retention::{matches_bool, EvaluationInputs, PolicyPredicate};

        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let oldest_hash = fixture_hash(0);
        let mut ids = Vec::new();
        for i in 0..5i64 {
            ids.push(
                seed_sibling(
                    &pool,
                    repo,
                    "pkg",
                    &format!("1.0.{i}"),
                    base + chrono::Duration::seconds(i),
                    &fixture_hash(u8::try_from(i).unwrap()),
                    Some("released"),
                    false,
                )
                .await,
            );
        }
        // The oldest version carries the repository's `latest` tag.
        seed_ref_to_hash(&pool, repo, "pkg", &oldest_hash).await;

        let rows = candidates_by_id(&pool, 1000).await;
        let predicate = PolicyPredicate::KeepLastN(2);
        let now = Utc::now();
        let matched: HashSet<Uuid> = rows
            .values()
            .filter(|row| {
                let inputs = EvaluationInputs {
                    now,
                    created_at: row.artifact.created_at,
                    last_downloaded_at: None,
                    keep_rank: row.keep_rank,
                    tag_targeted: row.tag_targeted,
                    findings: &[],
                    first_detected_at: row.artifact.created_at,
                    latest_scan_at: row.artifact.created_at,
                };
                matches_bool(&predicate, &inputs)
            })
            .map(|row| row.artifact.id)
            .collect();

        // ids[4], ids[3] are the two newest — inside the window.
        // ids[2] is rank 3 → marked. ids[1] is rank 4 → marked.
        // ids[0] is rank 5 but tagged → survives.
        assert_eq!(
            matched,
            HashSet::from([ids[2], ids[1]]),
            "ranks 1-2 are kept, the tag target is exempt, the rest are marked"
        );
    }
}
