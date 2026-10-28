//! `PgRetentionScanReader::list_findings_for_artifact` answers about the
//! artifact's **last** scan.
//!
//! `scan_findings` is per-scan history — every run writes its rows under a
//! fresh `scan_id` and nothing removes the previous run's — and this reader
//! feeds `RetentionUseCase`, whose predicate appends `ArtifactExpired`. So
//! a read over the union of every scan ever run lets a vulnerability a
//! later scan no longer reports drive a deletion.
//!
//! The anchor is `artifacts.last_scan_at`, which
//! `PgArtifactLifecycle::commit_scan_result_with_score` writes in the same
//! transaction as the per-finding rows from the same timestamp they carry
//! as `detected_at`. [`seed_scan`] reproduces exactly that pairing, which
//! is why it is a transaction and not two statements.
//!
//! `#[serial(hort_pg_db)]` is **mandatory** on every test that acquires a
//! real DB connection — CLAUDE.md "DB-backed test isolation
//! (parallel-safety contract)".
//!
//! DATABASE_URL-gated; every test early-returns silently when the env var
//! is unset.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test retention_scan_reader_last_scan
//! ```

#![allow(clippy::expect_used)]

use std::env;

use chrono::{DateTime, Duration, Utc};
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::retention_scan_reader::PgRetentionScanReader;
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::ports::retention_scan_reader::RetentionScanReader;
use hort_domain::retention::{
    matches_bool, EvaluationInputs, FindingAgeAnchor, FindingAgeAnchorSource, PolicyPredicate,
};

/// Per-test isolated database, migrated. `None` when `DATABASE_URL` is unset.
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

/// Truncate to microsecond precision so Rust's nanosecond clock and
/// Postgres' `timestamptz` column agree on the anchor value exactly.
fn truncate_us(t: DateTime<Utc>) -> DateTime<Utc> {
    let us = t.timestamp_micros();
    DateTime::<Utc>::from_timestamp_micros(us).expect("microsecond round-trip")
}

async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-retention-lastscan-{}", id.simple());
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

async fn seed_artifact(pool: &PgPool, repo: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let key = id.simple().to_string();
    let sha256 = format!("{key}{key}");
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key
           ) VALUES (
               $1, $2, 'retention-lastscan', 'retention-lastscan', '0.0.0', $3,
               0, $4, 'application/octet-stream', $4
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(format!("simple/retention-lastscan/{key}.tar.gz"))
    .bind(&sha256)
    .execute(pool)
    .await
    .expect("seed_artifact");
    id
}

/// Seed one scan: its `scan_findings` rows plus the
/// `artifacts.last_scan_at` advance, in ONE transaction — the pairing
/// `PgArtifactLifecycle::commit_scan_result_with_score` makes in
/// production, from the same timestamp the rows carry as `detected_at`.
///
/// `findings` is one `(vulnerability_id, severity, fixed_versions)` triple
/// per finding. An empty slice is a **clean scan**: no row is written and
/// the anchor still advances.
async fn seed_scan(
    pool: &PgPool,
    artifact_id: Uuid,
    detected_at: DateTime<Utc>,
    findings: &[(&str, &str, &[&str])],
) {
    let scan_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("seed_scan begin");
    for (vulnerability_id, severity, fixed_versions) in findings {
        let fixed: Vec<String> = fixed_versions.iter().map(|v| (*v).to_string()).collect();
        sqlx::query(
            r#"INSERT INTO public.scan_findings
                  (artifact_id, scan_id, purl, vulnerability_id, severity,
                   source_scanner, title, detected_at, fixed_versions)
               VALUES ($1, $2, $3, $4, $5, 'test-scanner', $6, $7, $8)"#,
        )
        .bind(artifact_id)
        .bind(scan_id)
        .bind(format!("pkg:pypi/{vulnerability_id}@1.0"))
        .bind(*vulnerability_id)
        .bind(*severity)
        .bind(format!("finding {vulnerability_id}"))
        .bind(detected_at)
        .bind(&fixed)
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

async fn row_count(pool: &PgPool, artifact_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM scan_findings WHERE artifact_id = $1")
        .bind(artifact_id)
        .fetch_one(pool)
        .await
        .expect("count scan_findings rows")
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn reads_only_the_last_scans_findings() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());

    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(3),
        &[("CVE-A", "critical", &[]), ("CVE-B", "high", &[])],
    )
    .await;
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(1),
        &[("CVE-C", "low", &[])],
    )
    .await;

    assert_eq!(row_count(&pool, artifact).await, 3, "history intact");

    let reader = PgRetentionScanReader::new(pool.clone());
    let findings = reader
        .list_findings_for_artifact(artifact)
        .await
        .expect("list findings");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vulnerability_id, "CVE-C");
    assert_eq!(findings[0].severity, SeverityThreshold::Low);

    // Item 7 — the read removes nothing.
    assert_eq!(row_count(&pool, artifact).await, 3);

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn a_clean_last_scan_reads_as_no_findings() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());

    // The clean run writes no row, so the newest `scan_id` present in the
    // table is still the dirty run's — the case no table-internal anchor
    // can answer.
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(2),
        &[("CVE-A", "critical", &["2.0.0"])],
    )
    .await;
    seed_scan(&pool, artifact, now - Duration::hours(1), &[]).await;

    let reader = PgRetentionScanReader::new(pool.clone());
    let findings = reader
        .list_findings_for_artifact(artifact)
        .await
        .expect("list findings");
    assert!(
        findings.is_empty(),
        "a finding the last scan no longer reports must drive no retention \
         decision; got {findings:?}"
    );

    // And the security-driven predicates that read this list do not fire.
    let inputs = EvaluationInputs {
        now,
        created_at: now - Duration::hours(10),
        last_downloaded_at: None,
        keep_rank: None,
        tag_targeted: false,
        findings: &findings,
        finding_age_anchor: Some(FindingAgeAnchor {
            known_since: now - Duration::hours(10),
            source: FindingAgeAnchorSource::FirstObservation,
        }),
        latest_scan_at: now - Duration::hours(1),
    };
    assert!(!matches_bool(&PolicyPredicate::HasFixAvailable, &inputs));
    assert!(!matches_bool(
        &PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::Low),
        &inputs
    ));

    // The earlier scan's row is still on disk.
    assert_eq!(row_count(&pool, artifact).await, 1);

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn a_retracted_fix_availability_stops_matching() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());

    // The first scan saw a fixable finding; the second reports the same
    // vulnerability with no fix. `HasFixAvailable` evaluated over the union
    // would still match on the stale row.
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(2),
        &[("CVE-A", "high", &["1.2.3"])],
    )
    .await;
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(1),
        &[("CVE-A", "high", &[])],
    )
    .await;

    let reader = PgRetentionScanReader::new(pool.clone());
    let findings = reader
        .list_findings_for_artifact(artifact)
        .await
        .expect("list findings");
    assert_eq!(findings.len(), 1);
    assert!(findings[0].fixed_versions.is_empty());

    let inputs = EvaluationInputs {
        now,
        created_at: now - Duration::hours(10),
        last_downloaded_at: None,
        keep_rank: None,
        tag_targeted: false,
        findings: &findings,
        finding_age_anchor: Some(FindingAgeAnchor {
            known_since: now - Duration::hours(10),
            source: FindingAgeAnchorSource::FirstObservation,
        }),
        latest_scan_at: now - Duration::hours(1),
    };
    assert!(!matches_bool(&PolicyPredicate::HasFixAvailable, &inputs));

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn the_last_scans_proper_subset_is_the_answer() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());

    // The counter-assertion. The second scan reports a proper subset of the
    // first — the Critical is gone, the High remains under its original
    // vulnerability id. Collapsing the history by de-duplicating
    // `vulnerability_id` returns both and still matches
    // `HasFindingAboveSeverity(High)`.
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(2),
        &[("CVE-A", "critical", &[]), ("CVE-B", "medium", &[])],
    )
    .await;
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(1),
        &[("CVE-B", "medium", &[])],
    )
    .await;

    let reader = PgRetentionScanReader::new(pool.clone());
    let findings = reader
        .list_findings_for_artifact(artifact)
        .await
        .expect("list findings");
    assert_eq!(
        findings.len(),
        1,
        "a DISTINCT-shaped fix would return two rows here; got {findings:?}"
    );
    assert_eq!(findings[0].vulnerability_id, "CVE-B");

    let inputs = EvaluationInputs {
        now,
        created_at: now - Duration::hours(10),
        last_downloaded_at: None,
        keep_rank: None,
        tag_targeted: false,
        findings: &findings,
        finding_age_anchor: Some(FindingAgeAnchor {
            known_since: now - Duration::hours(10),
            source: FindingAgeAnchorSource::FirstObservation,
        }),
        latest_scan_at: now - Duration::hours(1),
    };
    assert!(!matches_bool(
        &PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
        &inputs
    ));
    assert!(matches_bool(
        &PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::Medium),
        &inputs
    ));

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn a_never_scanned_artifact_reads_as_no_findings() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;

    // `last_scan_at` is NULL and there are no rows; the anchor's NULL
    // comparison must not surface as an error or a row.
    let reader = PgRetentionScanReader::new(pool.clone());
    let findings = reader
        .list_findings_for_artifact(artifact)
        .await
        .expect("list findings");
    assert!(findings.is_empty());

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn the_read_is_scoped_to_the_requested_artifact() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let mine = seed_artifact(&pool, repo_id).await;
    let other = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());

    // Both artifacts' last scans share one `detected_at`, which is the
    // shape that catches an anchor join written without the per-artifact
    // correlation: `sf.detected_at = a.last_scan_at` has to be `a` =
    // `sf`'s own artifact, not any artifact scanned at that instant.
    seed_scan(&pool, mine, now, &[("CVE-MINE", "low", &[])]).await;
    seed_scan(&pool, other, now, &[("CVE-OTHER", "critical", &[])]).await;

    let reader = PgRetentionScanReader::new(pool.clone());
    let findings = reader
        .list_findings_for_artifact(mine)
        .await
        .expect("list findings");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vulnerability_id, "CVE-MINE");

    cleanup(&pool, repo_id).await;
}
