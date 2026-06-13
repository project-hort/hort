//! PostgreSQL adapter for [`ScanFindingsRepository`] — the per-finding
//! `scan_findings` projection from migration 009.
//!
//! Every per-finding row lands inside the same Postgres transaction as
//! the corresponding `ScanCompleted` event append. The transactional
//! boundary is owned by
//! [`crate::artifact_lifecycle::PgArtifactLifecycle::commit_scan_result`];
//! callers that exercise the trait outside that lifecycle path get a
//! standalone (single-statement) insert here.

use sqlx::{PgPool, Postgres, QueryBuilder};

use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::scan_findings_repository::{ScanFindingsRepository, ScanFindingsRow};

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL adapter for [`ScanFindingsRepository`].
pub struct PgScanFindingsRepository {
    pool: PgPool,
}

impl PgScanFindingsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Render a [`SeverityThreshold`] into the `severity` enum literal the
/// migration 009 CHECK constraint expects (`'critical' | 'high' |
/// 'medium' | 'low' | 'negligible'`). `Finding` carries
/// `SeverityThreshold` which has no `Negligible` variant; the column
/// supports it for symmetry with the aggregate severity catalog.
pub(crate) fn severity_to_sql(s: SeverityThreshold) -> &'static str {
    match s {
        SeverityThreshold::Critical => "critical",
        SeverityThreshold::High => "high",
        SeverityThreshold::Medium => "medium",
        SeverityThreshold::Low => "low",
    }
}

/// Insert a batch of scan findings into the projection table within
/// `tx`. Used by `PgArtifactLifecycle::commit_scan_result` to keep the
/// rows in the same transaction as the event append + artifact state
/// mutation + `last_scan_at` write.
///
/// Empty input returns `Ok(())` without issuing a query — the
/// no-findings fast path on a clean scan must not generate stray SQL.
pub(crate) async fn insert_findings_in_tx(
    tx: &mut sqlx::PgConnection,
    rows: &[ScanFindingsRow],
) -> DomainResult<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "INSERT INTO scan_findings (\
            artifact_id, scan_id, purl, vulnerability_id, severity, \
            cvss_score, source_scanner, title, detected_at\
        ) ",
    );
    qb.push_values(rows, |mut b, row| {
        b.push_bind(row.artifact_id)
            .push_bind(row.scan_id)
            .push_bind(&row.purl)
            .push_bind(&row.vulnerability_id)
            .push_bind(severity_to_sql(row.severity))
            .push_bind(row.cvss_score)
            .push_bind(&row.source_scanner)
            .push_bind(&row.title)
            .push_bind(row.detected_at);
    });
    let query = qb.build();
    query
        .execute(&mut *tx)
        .await
        .map_err(|e| map_sqlx_error(&e, "scan_findings", ""))?;
    Ok(())
}

impl ScanFindingsRepository for PgScanFindingsRepository {
    fn insert_batch<'a>(&'a self, rows: &'a [ScanFindingsRow]) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            if rows.is_empty() {
                return Ok(());
            }
            let mut tx = self.pool.begin().await.map_err(|e| {
                DomainError::Invariant(format!("scan_findings insert_batch begin tx: {e}"))
            })?;
            insert_findings_in_tx(&mut tx, rows).await?;
            tx.commit().await.map_err(|e| {
                DomainError::Invariant(format!("scan_findings insert_batch commit: {e}"))
            })?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serial_test::serial;
    use sqlx::PgPool;
    use std::env;
    use uuid::Uuid;

    /// Compile-time assertion that the Postgres adapter implements the
    /// port — keeps the dyn cast working when tests don't actually
    /// connect to a database.
    #[test]
    fn pg_adapter_implements_port() {
        fn assert_impl<T: ScanFindingsRepository>() {}
        assert_impl::<PgScanFindingsRepository>();
    }

    /// Seed a `repositories` row with random-but-valid identifiers.
    /// Mirrors `tests/migration_009_jobs_and_findings.rs::seed_repo` so
    /// FK-dependent unit tests in this file have a real parent without
    /// dragging in test_support infrastructure.
    async fn seed_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("it-scanfindings-{}", id.simple());
        sqlx::query(
            r#"INSERT INTO public.repositories (
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
        .expect("seed_repo");
        id
    }

    /// Seed an `artifacts` row owned by `repo`. The 64-char "checksum"
    /// is a deterministic UUID-derived hex blob — not a real SHA-256.
    async fn seed_artifact(pool: &PgPool, repo: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        let key = id.simple().to_string();
        let sha256 = format!("{key}{key}");
        sqlx::query(
            r#"INSERT INTO public.artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key
               ) VALUES (
                   $1, $2, 'scan-find-it', 'scan-find-it', '0.0.0', $3,
                   0, $4, 'application/octet-stream', $4
               )"#,
        )
        .bind(id)
        .bind(repo)
        .bind(format!("simple/scan-find-it/{key}.tar.gz"))
        .bind(&sha256)
        .execute(pool)
        .await
        .expect("seed_artifact");
        id
    }

    /// Round-trip every `SeverityThreshold` variant through the SQL
    /// literal mapping. The CHECK constraint in migration 009 will
    /// reject anything outside the allowed set.
    #[test]
    fn severity_to_sql_covers_all_variants() {
        assert_eq!(severity_to_sql(SeverityThreshold::Critical), "critical");
        assert_eq!(severity_to_sql(SeverityThreshold::High), "high");
        assert_eq!(severity_to_sql(SeverityThreshold::Medium), "medium");
        assert_eq!(severity_to_sql(SeverityThreshold::Low), "low");
    }

    /// Pin: an empty rows slice never issues SQL. The transactional
    /// helper short-circuits before query construction.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn insert_findings_in_tx_empty_is_noop() {
        // We cannot construct a `PgConnection` without a live DB, so
        // we exercise the early-return path through the public trait
        // method which mirrors the same shortcut.
        let Ok(url) = env::var("DATABASE_URL") else {
            return;
        };
        let Ok(pool) = PgPool::connect(&url).await else {
            return;
        };
        let repo = PgScanFindingsRepository::new(pool);
        repo.insert_batch(&[])
            .await
            .expect("empty insert_batch must not fail");
    }

    /// DB-backed: insert a row, verify it lands. Gated on
    /// `DATABASE_URL` so unit-only runs skip cleanly.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn insert_one_row_round_trip() {
        let Ok(url) = env::var("DATABASE_URL") else {
            return;
        };
        let Ok(pool) = PgPool::connect(&url).await else {
            return;
        };
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run");

        // Seed a real repository + artifact so the FK on
        // `scan_findings.artifact_id → artifacts(id)` (migration 009,
        // M4) holds. Pre-M4 this used a free-floating Uuid::new_v4().
        let repo_id = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = Uuid::new_v4();
        let row = ScanFindingsRow {
            artifact_id,
            scan_id,
            purl: format!("pkg:npm/it-{}@1", artifact_id.simple()),
            vulnerability_id: "CVE-IT-1".into(),
            severity: SeverityThreshold::High,
            cvss_score: Some(7.0),
            source_scanner: "trivy".into(),
            title: "test".into(),
            detected_at: Utc::now(),
        };

        let repo = PgScanFindingsRepository::new(pool.clone());
        repo.insert_batch(std::slice::from_ref(&row))
            .await
            .expect("insert_batch");

        // Verify presence.
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM scan_findings WHERE artifact_id = $1 AND scan_id = $2",
        )
        .bind(artifact_id)
        .bind(scan_id)
        .fetch_one(&pool)
        .await
        .expect("count query");
        assert_eq!(count, 1);

        // Cleanup so reruns stay deterministic. Deleting the repository
        // cascades through artifacts and scan_findings (M3 + M4).
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
    }

    /// DB-backed: a duplicate primary key surfaces as a Conflict
    /// (idempotency contract — see port docstring).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn duplicate_row_surfaces_conflict() {
        let Ok(url) = env::var("DATABASE_URL") else {
            return;
        };
        let Ok(pool) = PgPool::connect(&url).await else {
            return;
        };
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run");

        let repo_id = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = Uuid::new_v4();
        let row = ScanFindingsRow {
            artifact_id,
            scan_id,
            purl: "pkg:npm/dup@1".into(),
            vulnerability_id: "CVE-DUP-1".into(),
            severity: SeverityThreshold::Critical,
            cvss_score: None,
            source_scanner: "trivy".into(),
            title: "dup".into(),
            detected_at: Utc::now(),
        };

        let repo = PgScanFindingsRepository::new(pool.clone());
        repo.insert_batch(std::slice::from_ref(&row))
            .await
            .expect("first insert");
        let err = repo
            .insert_batch(std::slice::from_ref(&row))
            .await
            .expect_err("second insert must fail");
        assert!(
            matches!(err, DomainError::Conflict(_)) || err.to_string().contains("duplicate"),
            "expected Conflict, got: {err:?}"
        );

        // Cascade cleanup via the repository row (M3 + M4).
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
    }
}
