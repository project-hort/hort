//! `PgPatchCandidateRepository` integration tests.
//!
//! Exercises the patch-candidate query end-to-end against a real Postgres. The
//! four acceptance scenarios (basic detection, repository filter, OCI
//! exclusion, severity ordering) each get their own `#[tokio::test]`.
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

use serial_test::serial;
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
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
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
    sqlx::query(sqlx::AssertSqlSafe(sql))
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
async fn seed_artifact(
    pool: &PgPool,
    repo: Uuid,
    name: &str,
    version: &str,
    quarantine_status: Option<&str>,
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
               quarantine_status, created_at, updated_at
           ) VALUES (
               $1, $2, $3, $3, $4, $5,
               0, $6, 'application/octet-stream', $6,
               $7, $8, $8
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(name)
    .bind(version)
    .bind(format!("{name}/{version}/{key}.tgz"))
    .bind(&sha256)
    .bind(quarantine_status)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed_artifact");
    id
}

/// Truncate a `DateTime<Utc>` to microsecond precision so Rust's
/// nanosecond clock and Postgres' `timestamptz` column agree on the exact
/// value the last-scan anchor is compared against.
fn truncate_us(t: DateTime<Utc>) -> DateTime<Utc> {
    let us = t.timestamp_micros();
    DateTime::<Utc>::from_timestamp_micros(us).expect("microsecond round-trip")
}

/// Seed one scan: its `scan_findings` rows plus the
/// `artifacts.last_scan_at` advance, in one transaction.
///
/// This is the pairing `PgArtifactLifecycle::commit_scan_result_with_score`
/// makes in production — the per-finding rows and the `last_scan_at` write
/// land in the same SQL transaction, bound from the same timestamp the rows
/// carry as `detected_at`. The candidacy query's findings LATERAL anchors on
/// exactly that equality, so a seeder that wrote rows without advancing the
/// anchor would be seeding a state no scan can produce.
///
/// `vulnerabilities` is one `(vulnerability_id, severity)` pair per finding.
/// An empty slice is a **clean scan**: no row is written and the anchor still
/// advances.
async fn seed_scan(
    pool: &PgPool,
    artifact_id: Uuid,
    detected_at: DateTime<Utc>,
    vulnerabilities: &[(&str, &str)],
) {
    let scan_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("seed_scan begin");
    for (vulnerability_id, severity) in vulnerabilities {
        sqlx::query(
            r#"INSERT INTO public.scan_findings
                  (artifact_id, scan_id, purl, vulnerability_id, severity,
                   source_scanner, title, detected_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(artifact_id)
        .bind(scan_id)
        .bind(format!("pkg:test/{}@1.0", artifact_id.simple()))
        .bind(*vulnerability_id)
        .bind(*severity)
        .bind("test-scanner")
        .bind("integration-test finding")
        .bind(detected_at)
        .execute(&mut *tx)
        .await
        .expect("seed_scan finding row");
    }
    sqlx::query("UPDATE public.artifacts SET last_scan_at = $1 WHERE id = $2")
        .bind(detected_at)
        .bind(artifact_id)
        .execute(&mut *tx)
        .await
        .expect("seed_scan last_scan_at");
    tx.commit().await.expect("seed_scan commit");
}

/// One scan reporting one finding at `severity`, committed now. The shape
/// most tests here want; multi-scan histories call [`seed_scan`] directly.
async fn seed_finding(pool: &PgPool, artifact_id: Uuid, severity: &str) {
    let vuln = format!("CVE-TEST-{}", artifact_id.simple());
    seed_scan(
        pool,
        artifact_id,
        truncate_us(Utc::now()),
        &[(vuln.as_str(), severity)],
    )
    .await;
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
#[serial(hort_pg_db)]
async fn list_candidates_default_filter_returns_matching_pair() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let t_released = Utc::now() - Duration::hours(2);
    let t_quarantined = Utc::now() - Duration::hours(1);

    let pkg_v1_0 = seed_artifact(&pool, repo_id, "pkg", "1.0", Some("released"), t_released).await;
    let pkg_v1_1 = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.1",
        Some("quarantined"),
        t_quarantined,
    )
    .await;
    let _other_v1_0 =
        seed_artifact(&pool, repo_id, "other", "1.0", Some("released"), t_released).await;
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
#[serial(hort_pg_db)]
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
        t_released,
    )
    .await;
    let _pkg_v1_1 = seed_artifact(
        &pool,
        repo_with_pair,
        "pkg",
        "1.1",
        Some("quarantined"),
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
#[serial(hort_pg_db)]
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
        t_released,
    )
    .await;
    let pkg_v1_1 = seed_artifact(
        &pool,
        oci_repo,
        "image",
        "1.1",
        Some("quarantined"),
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
// Test 4 — ORDER BY max_severity_rank DESC: a Critical-severity sibling
// sorts before a High-severity sibling.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_candidates_orders_by_severity_descending() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let t_released = Utc::now() - Duration::hours(2);
    let t_quarantined = Utc::now() - Duration::hours(1);

    // The High-severity pkg pair (test #1 reproducer).
    let pkg_v1_0 = seed_artifact(&pool, repo_id, "pkg", "1.0", Some("released"), t_released).await;
    let pkg_v1_1 = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.1",
        Some("quarantined"),
        t_quarantined,
    )
    .await;
    seed_finding(&pool, pkg_v1_0, "high").await;

    // The Critical-severity lib pair.
    let lib_v1_0 = seed_artifact(&pool, repo_id, "lib", "1.0", Some("released"), t_released).await;
    let lib_v1_1 = seed_artifact(
        &pool,
        repo_id,
        "lib",
        "1.1",
        Some("quarantined"),
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

// ---------------------------------------------------------------------------
// The candidacy summary — and the ORDER BY built on it — answer about the
// released predecessor's LAST scan.
//
// `scan_findings` is per-scan history, so a summary filtered on
// `artifact_id` alone grows with the rescan count. On this surface that
// does not merely mis-report a number: the listing orders by
// `max_severity_rank`, so a severity no later scan reports would outrank a
// genuinely worse candidate, and a predecessor whose findings were all
// retracted would keep being offered as the thing to patch towards.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_candidates_summary_is_the_last_scan_not_the_union() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let t_released = truncate_us(Utc::now() - Duration::hours(5));
    let t_quarantined = truncate_us(Utc::now() - Duration::hours(4));

    let pkg_v1_0 = seed_artifact(&pool, repo_id, "pkg", "1.0", Some("released"), t_released).await;
    let _pkg_v1_1 = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.1",
        Some("quarantined"),
        t_quarantined,
    )
    .await;

    // Two scans on the released row: a critical pair, then a single low.
    // The union is three rows / Critical; the last scan is one row / Low.
    seed_scan(
        &pool,
        pkg_v1_0,
        truncate_us(Utc::now() - Duration::hours(3)),
        &[("CVE-A", "critical"), ("CVE-B", "high")],
    )
    .await;
    seed_scan(
        &pool,
        pkg_v1_0,
        truncate_us(Utc::now() - Duration::hours(2)),
        &[("CVE-C", "low")],
    )
    .await;

    let adapter = PgPatchCandidateRepository::new(pool.clone());
    let rows = adapter
        .list_candidates(PatchCandidateFilter {
            repository_id: Some(repo_id),
            ..PatchCandidateFilter::default()
        })
        .await
        .expect("list_candidates");

    assert_eq!(rows.len(), 1, "one quarantined/released pair");
    assert_eq!(rows[0].vulnerable_finding_count, 1);
    assert_eq!(
        rows[0].vulnerable_max_severity,
        Some(SeverityThreshold::Low),
        "the ranked severity is the last scan's, not the all-time highest"
    );

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_candidates_clean_last_scan_drops_the_pair() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let t_released = truncate_us(Utc::now() - Duration::hours(5));
    let t_quarantined = truncate_us(Utc::now() - Duration::hours(4));

    let pkg_v1_0 = seed_artifact(&pool, repo_id, "pkg", "1.0", Some("released"), t_released).await;
    let _pkg_v1_1 = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.1",
        Some("quarantined"),
        t_quarantined,
    )
    .await;

    // Dirty, then clean. The clean run writes no row, so the only thing
    // that can tell this apart from "still dirty" is the anchor on
    // `artifacts.last_scan_at`.
    seed_scan(
        &pool,
        pkg_v1_0,
        truncate_us(Utc::now() - Duration::hours(3)),
        &[("CVE-A", "critical")],
    )
    .await;
    seed_scan(
        &pool,
        pkg_v1_0,
        truncate_us(Utc::now() - Duration::hours(2)),
        &[],
    )
    .await;

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
        "the released predecessor's last scan reports nothing, so it is not \
         a vulnerable row to patch away from; got {rows:?}"
    );

    // The history is intact — the pair dropped out of the listing, no row
    // was removed.
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM scan_findings WHERE artifact_id = $1")
            .bind(pkg_v1_0)
            .fetch_one(&pool)
            .await
            .expect("count all rows");
    assert_eq!(total, 1);

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_candidates_order_follows_the_last_scan_severity() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let t_released = truncate_us(Utc::now() - Duration::hours(5));
    let t_quarantined = truncate_us(Utc::now() - Duration::hours(4));
    let t_first = truncate_us(Utc::now() - Duration::hours(3));
    let t_last = truncate_us(Utc::now() - Duration::hours(2));

    // `pkg`'s released row once carried a Critical and now carries a Low.
    // `lib`'s released row has only ever carried a High. Ordered on the
    // union, `pkg` leads; ordered on the last scan — which is what the
    // verdicts are derived from — `lib` does.
    let pkg_v1_0 = seed_artifact(&pool, repo_id, "pkg", "1.0", Some("released"), t_released).await;
    let _pkg_v1_1 = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.1",
        Some("quarantined"),
        t_quarantined,
    )
    .await;
    seed_scan(&pool, pkg_v1_0, t_first, &[("CVE-A", "critical")]).await;
    seed_scan(&pool, pkg_v1_0, t_last, &[("CVE-B", "low")]).await;

    let lib_v1_0 = seed_artifact(&pool, repo_id, "lib", "1.0", Some("released"), t_released).await;
    let _lib_v1_1 = seed_artifact(
        &pool,
        repo_id,
        "lib",
        "1.1",
        Some("quarantined"),
        t_quarantined,
    )
    .await;
    seed_scan(&pool, lib_v1_0, t_last, &[("CVE-C", "high")]).await;

    let adapter = PgPatchCandidateRepository::new(pool.clone());
    let rows = adapter
        .list_candidates(PatchCandidateFilter {
            repository_id: Some(repo_id),
            ..PatchCandidateFilter::default()
        })
        .await
        .expect("list_candidates");

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].package_name, "lib");
    assert_eq!(
        rows[0].vulnerable_max_severity,
        Some(SeverityThreshold::High)
    );
    assert_eq!(rows[1].package_name, "pkg");
    assert_eq!(
        rows[1].vulnerable_max_severity,
        Some(SeverityThreshold::Low)
    );

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_candidates_last_scan_subset_is_the_subset_not_the_union() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let t_released = truncate_us(Utc::now() - Duration::hours(5));
    let t_quarantined = truncate_us(Utc::now() - Duration::hours(4));

    let pkg_v1_0 = seed_artifact(&pool, repo_id, "pkg", "1.0", Some("released"), t_released).await;
    let _pkg_v1_1 = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.1",
        Some("quarantined"),
        t_quarantined,
    )
    .await;

    // The counter-assertion: the second scan reports a proper subset of
    // the first, dropping the severe one. A DISTINCT over
    // `vulnerability_id` would answer 2 / Critical.
    seed_scan(
        &pool,
        pkg_v1_0,
        truncate_us(Utc::now() - Duration::hours(3)),
        &[("CVE-A", "critical"), ("CVE-B", "medium")],
    )
    .await;
    seed_scan(
        &pool,
        pkg_v1_0,
        truncate_us(Utc::now() - Duration::hours(2)),
        &[("CVE-B", "medium")],
    )
    .await;

    let adapter = PgPatchCandidateRepository::new(pool.clone());
    let rows = adapter
        .list_candidates(PatchCandidateFilter {
            repository_id: Some(repo_id),
            ..PatchCandidateFilter::default()
        })
        .await
        .expect("list_candidates");

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].vulnerable_finding_count, 1);
    assert_eq!(
        rows[0].vulnerable_max_severity,
        Some(SeverityThreshold::Medium)
    );

    cleanup(&pool, repo_id).await;
}
