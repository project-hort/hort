//! `PgPatchCandidateRepository` integration tests.
//!
//! Exercises the patch-candidate query end-to-end against a real Postgres. The
//! five acceptance scenarios (basic detection, repository filter, OCI
//! exclusion, soft-delete exclusion, severity ordering) each get their
//! own `#[tokio::test]`.
//!
//! DATABASE_URL-gated; every test early-returns silently when the env
//! var is unset so dev environments without a database keep the suite
//! green. Mirrors the convention in `repo_security_score_repository.rs`.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test patch_candidate_repo
//! ```

#![allow(clippy::expect_used)]

use std::env;

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::patch_candidate_repo::PgPatchCandidateRepository;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::ports::patch_candidate_repository::{
    PatchCandidateFilter, PatchCandidateRepository,
};

/// Connect as the migration superuser; run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");
    Some(pool)
}

/// Seed a `repositories` row with the given `format` and return its id.
/// Each test uses unique UUIDs so concurrent runs don't collide.
async fn seed_repo(pool: &PgPool, format_literal: &'static str) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-init36-{}", id.simple());
    let format_sql = format!("'{format_literal}'::repository_format");
    let sql = format!(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $3,
               {format_sql},
               'hosted'::repository_type,
               'filesystem', $4,
               'local_only'::replication_priority
           )"#
    );
    sqlx::query(&sql)
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .execute(pool)
        .await
        .expect("seed_repo");
    id
}

/// Seed an artifact row. `created_at` lets tests order the released
/// predecessor strictly before the quarantined sibling (the query
/// requires `v.created_at < q.created_at`).
#[allow(clippy::too_many_arguments)]
async fn seed_artifact(
    pool: &PgPool,
    repo: Uuid,
    name: &str,
    version: &str,
    quarantine_status: Option<&str>,
    is_deleted: bool,
    created_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    let key = id.simple().to_string();
    // 64-char hex blob from the UUID — `checksum_sha256 CHAR(64)` requires
    // exactly 64 chars; doubling the 32-char simple form is sufficient.
    let sha256 = format!("{key}{key}");
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key,
               quarantine_status, is_deleted, created_at, updated_at
           ) VALUES (
               $1, $2, $3, $3, $4, $5,
               0, $6, 'application/octet-stream', $6,
               $7, $8, $9, $9
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(name)
    .bind(version)
    .bind(format!("{name}/{version}/{key}.tgz"))
    .bind(&sha256)
    .bind(quarantine_status)
    .bind(is_deleted)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed_artifact");
    id
}

/// Seed one `scan_findings` row for `artifact_id` at the given severity.
async fn seed_finding(pool: &PgPool, artifact_id: Uuid, severity: &str) {
    sqlx::query(
        r#"INSERT INTO public.scan_findings
              (artifact_id, scan_id, purl, vulnerability_id, severity,
               source_scanner, title, detected_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, now())"#,
    )
    .bind(artifact_id)
    .bind(Uuid::new_v4())
    .bind(format!("pkg:test/{}@1.0", artifact_id.simple()))
    .bind(format!("CVE-TEST-{}", artifact_id.simple()))
    .bind(severity)
    .bind("test-scanner")
    .bind("integration-test finding")
    .execute(pool)
    .await
    .expect("seed_finding");
}

/// Drop the repository, cascading through `artifacts` and
/// `scan_findings` (both FK ON DELETE CASCADE).
async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

// ---------------------------------------------------------------------------
// Test 1 — default filter returns the pkg@1.1 quarantined / pkg@1.0
// released pair with finding_count=1, max_severity=High.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_candidates_default_filter_returns_matching_pair() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let t_released = Utc::now() - Duration::hours(2);
    let t_quarantined = Utc::now() - Duration::hours(1);

    let pkg_v1_0 = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("released"),
        false,
        t_released,
    )
    .await;
    let pkg_v1_1 = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.1",
        Some("quarantined"),
        false,
        t_quarantined,
    )
    .await;
    let _other_v1_0 = seed_artifact(
        &pool,
        repo_id,
        "other",
        "1.0",
        Some("released"),
        false,
        t_released,
    )
    .await;
    seed_finding(&pool, pkg_v1_0, "high").await;

    let adapter = PgPatchCandidateRepository::new(pool.clone());
    let rows = adapter
        .list_candidates(PatchCandidateFilter::default())
        .await
        .expect("list_candidates");

    // Only this repo's rows might be visible; if other repos in the
    // DB also have candidates, filter to this seeded pair.
    let row = rows
        .into_iter()
        .find(|c| c.quarantined_artifact_id == pkg_v1_1)
        .expect("seeded pair must be in the result set");

    assert_eq!(row.quarantined_artifact_id, pkg_v1_1);
    assert_eq!(row.vulnerable_artifact_id, pkg_v1_0);
    assert_eq!(row.vulnerable_finding_count, 1);
    assert_eq!(row.vulnerable_max_severity, Some(SeverityThreshold::High));
    assert_eq!(row.repository_id, repo_id);
    assert_eq!(row.format, RepositoryFormat::Npm);
    assert_eq!(row.package_name, "pkg");
    assert_eq!(row.quarantined_status, QuarantineStatus::Quarantined);
    assert_eq!(row.quarantined_version.as_deref(), Some("1.1"));
    assert_eq!(row.vulnerable_version.as_deref(), Some("1.0"));

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 2 — filter to a repo that has no candidates returns empty Vec.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_candidates_repository_filter_excludes_other_repos() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_with_pair = seed_repo(&pool, "npm").await;
    let empty_repo = seed_repo(&pool, "pypi").await;
    let t_released = Utc::now() - Duration::hours(2);
    let t_quarantined = Utc::now() - Duration::hours(1);

    let pkg_v1_0 = seed_artifact(
        &pool,
        repo_with_pair,
        "pkg",
        "1.0",
        Some("released"),
        false,
        t_released,
    )
    .await;
    let _pkg_v1_1 = seed_artifact(
        &pool,
        repo_with_pair,
        "pkg",
        "1.1",
        Some("quarantined"),
        false,
        t_quarantined,
    )
    .await;
    seed_finding(&pool, pkg_v1_0, "high").await;

    let adapter = PgPatchCandidateRepository::new(pool.clone());
    let rows = adapter
        .list_candidates(PatchCandidateFilter {
            repository_id: Some(empty_repo),
            ..PatchCandidateFilter::default()
        })
        .await
        .expect("list_candidates");

    assert!(
        rows.is_empty(),
        "filter to empty repo must return no candidates; got {} rows",
        rows.len()
    );

    cleanup(&pool, repo_with_pair).await;
    cleanup(&pool, empty_repo).await;
}

// ---------------------------------------------------------------------------
// Test 3 — OCI repos are excluded from the result set
// (`r.format <> 'oci'`).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_candidates_excludes_oci_format() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let oci_repo = seed_repo(&pool, "oci").await;
    let t_released = Utc::now() - Duration::hours(2);
    let t_quarantined = Utc::now() - Duration::hours(1);

    let pkg_v1_0 = seed_artifact(
        &pool,
        oci_repo,
        "image",
        "1.0",
        Some("released"),
        false,
        t_released,
    )
    .await;
    let pkg_v1_1 = seed_artifact(
        &pool,
        oci_repo,
        "image",
        "1.1",
        Some("quarantined"),
        false,
        t_quarantined,
    )
    .await;
    seed_finding(&pool, pkg_v1_0, "high").await;

    let adapter = PgPatchCandidateRepository::new(pool.clone());
    // Filter to this repo specifically so we don't pick up unrelated
    // candidates from other repos in the test DB.
    let rows = adapter
        .list_candidates(PatchCandidateFilter {
            repository_id: Some(oci_repo),
            ..PatchCandidateFilter::default()
        })
        .await
        .expect("list_candidates");

    assert!(
        rows.is_empty(),
        "OCI format must be filtered out; got {} rows. \
         Any row from the seeded oci repo would surface as format == Oci.",
        rows.len()
    );
    // Also confirm the seeded pair would have matched if format were
    // not 'oci' — by inspecting the artifacts table directly.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM artifacts WHERE id IN ($1, $2)")
            .bind(pkg_v1_0)
            .bind(pkg_v1_1)
            .fetch_one(&pool)
            .await
            .expect("count seeded artifacts");
    assert_eq!(count, 2, "both seeded artifacts must exist in the DB");

    cleanup(&pool, oci_repo).await;
}

// ---------------------------------------------------------------------------
// Test 4 — soft-deleted quarantined rows are excluded
// (`q.is_deleted = false`).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_candidates_excludes_soft_deleted_quarantined_rows() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let t_released = Utc::now() - Duration::hours(2);
    let t_quarantined = Utc::now() - Duration::hours(1);

    let pkg2_v1_0 = seed_artifact(
        &pool,
        repo_id,
        "pkg2",
        "1.0",
        Some("released"),
        false,
        t_released,
    )
    .await;
    let pkg2_v1_1_deleted = seed_artifact(
        &pool,
        repo_id,
        "pkg2",
        "1.1",
        Some("quarantined"),
        true, // is_deleted
        t_quarantined,
    )
    .await;
    seed_finding(&pool, pkg2_v1_0, "high").await;

    let adapter = PgPatchCandidateRepository::new(pool.clone());
    let rows = adapter
        .list_candidates(PatchCandidateFilter {
            repository_id: Some(repo_id),
            ..PatchCandidateFilter::default()
        })
        .await
        .expect("list_candidates");

    assert!(
        rows.is_empty(),
        "soft-deleted quarantined row must not surface, and there are no \
         other quarantined siblings in this scenario, so result must be empty \
         (got {rows:#?})"
    );
    assert!(
        rows.iter()
            .all(|c| c.quarantined_artifact_id != pkg2_v1_1_deleted),
        "soft-deleted quarantined row must not surface as a candidate"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 5 — ORDER BY max_severity_rank DESC: a Critical-severity sibling
// sorts before a High-severity sibling.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_candidates_orders_by_severity_descending() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let t_released = Utc::now() - Duration::hours(2);
    let t_quarantined = Utc::now() - Duration::hours(1);

    // The High-severity pkg pair (test #1 reproducer).
    let pkg_v1_0 = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("released"),
        false,
        t_released,
    )
    .await;
    let pkg_v1_1 = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.1",
        Some("quarantined"),
        false,
        t_quarantined,
    )
    .await;
    seed_finding(&pool, pkg_v1_0, "high").await;

    // The Critical-severity lib pair.
    let lib_v1_0 = seed_artifact(
        &pool,
        repo_id,
        "lib",
        "1.0",
        Some("released"),
        false,
        t_released,
    )
    .await;
    let lib_v1_1 = seed_artifact(
        &pool,
        repo_id,
        "lib",
        "1.1",
        Some("quarantined"),
        false,
        t_quarantined,
    )
    .await;
    seed_finding(&pool, lib_v1_0, "critical").await;

    let adapter = PgPatchCandidateRepository::new(pool.clone());
    let rows = adapter
        .list_candidates(PatchCandidateFilter {
            repository_id: Some(repo_id),
            ..PatchCandidateFilter::default()
        })
        .await
        .expect("list_candidates");

    let critical_idx = rows
        .iter()
        .position(|c| c.quarantined_artifact_id == lib_v1_1)
        .expect("Critical pair must appear in results");
    let high_idx = rows
        .iter()
        .position(|c| c.quarantined_artifact_id == pkg_v1_1)
        .expect("High pair must appear in results");

    assert!(
        critical_idx < high_idx,
        "Critical (lib@1.1, idx={critical_idx}) must sort before High (pkg@1.1, idx={high_idx})"
    );
    assert_eq!(
        rows[critical_idx].vulnerable_max_severity,
        Some(SeverityThreshold::Critical)
    );
    assert_eq!(
        rows[high_idx].vulnerable_max_severity,
        Some(SeverityThreshold::High)
    );

    cleanup(&pool, repo_id).await;
}
