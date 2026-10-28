//! `PgRetentionScanReader`'s two halves of the finding-age anchor: the
//! advisory publication date it projects out of `scan_findings`, and the
//! `first_observed_at` read that dates a named vulnerability across every
//! scan the artifact has had.
//!
//! The anchor answers **how long the vulnerability has been known**. The
//! publication date is the only source that dates the vulnerability
//! itself; the first observation is our own bound on it. Neither is
//! answerable from the artifact's last scan alone, which is why this read
//! is the one `scan_findings` reader that spans scans — see the
//! `-- HISTORY-WIDE:` declaration on the statement and
//! `hort-app/tests/findings_reads_are_last_scan_scoped.rs` for what that
//! declaration is and is not for.
//!
//! The safety property these tests pin is the *keying*: the read answers
//! only about the ids it was handed, which the caller takes from the
//! artifact's LAST scan. A retracted vulnerability is therefore never
//! asked about, so its history cannot reach a retention deletion.
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
//!   cargo test -p hort-adapters-postgres --test retention_finding_age_anchor
//! ```

#![allow(clippy::expect_used)]

use std::env;

use chrono::{DateTime, Duration, Utc};
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::retention_scan_reader::PgRetentionScanReader;
use hort_domain::ports::retention_scan_reader::RetentionScanReader;
use hort_domain::retention::{resolve_finding_age_anchor, FindingAgeAnchorSource, PolicyPredicate};

/// Per-test isolated database, migrated. `None` when `DATABASE_URL` is unset.
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

/// Truncate to microsecond precision so Rust's nanosecond clock and
/// Postgres' `timestamptz` column agree exactly.
fn truncate_us(t: DateTime<Utc>) -> DateTime<Utc> {
    let us = t.timestamp_micros();
    DateTime::<Utc>::from_timestamp_micros(us).expect("microsecond round-trip")
}

async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-finding-age-{}", id.simple());
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
               $1, $2, 'finding-age', 'finding-age', '0.0.0', $3,
               0, $4, 'application/octet-stream', $4
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(format!("simple/finding-age/{key}.tar.gz"))
    .bind(&sha256)
    .execute(pool)
    .await
    .expect("seed_artifact");
    id
}

/// One seeded finding row: `(vulnerability_id, source_scanner,
/// advisory_published_at)`.
type SeedFinding<'a> = (&'a str, &'a str, Option<DateTime<Utc>>);

/// Seed one scan: its `scan_findings` rows plus the
/// `artifacts.last_scan_at` advance, in ONE transaction — the pairing
/// `PgArtifactLifecycle::commit_scan_result_with_score` makes in
/// production, from the same timestamp the rows carry as `detected_at`.
async fn seed_scan(
    pool: &PgPool,
    artifact_id: Uuid,
    detected_at: DateTime<Utc>,
    findings: &[SeedFinding<'_>],
) {
    let scan_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("seed_scan begin");
    for (vulnerability_id, source_scanner, published) in findings {
        sqlx::query(
            r#"INSERT INTO public.scan_findings
                  (artifact_id, scan_id, purl, vulnerability_id, severity,
                   source_scanner, title, detected_at, fixed_versions,
                   advisory_published_at)
               VALUES ($1, $2, $3, $4, 'high', $5, $6, $7, '{}'::text[], $8)"#,
        )
        .bind(artifact_id)
        .bind(scan_id)
        .bind(format!("pkg:pypi/{vulnerability_id}@1.0"))
        .bind(*vulnerability_id)
        .bind(*source_scanner)
        .bind(format!("finding {vulnerability_id}"))
        .bind(detected_at)
        .bind(*published)
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

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

/// `MIN(detected_at)` spans scans. The last scan's rows all carry that
/// scan's `detected_at`, so a last-scan-scoped read would answer "when
/// was the last scan" — which is the defect this read exists to avoid,
/// not a narrower version of the right answer.
#[tokio::test]
#[serial(hort_pg_db)]
async fn first_observed_at_is_the_earliest_detection_across_scans() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());

    seed_scan(
        &pool,
        artifact,
        now - Duration::days(30),
        &[("CVE-A", "osv", None)],
    )
    .await;
    seed_scan(
        &pool,
        artifact,
        now - Duration::days(10),
        &[("CVE-A", "osv", None)],
    )
    .await;
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(1),
        &[("CVE-A", "osv", None)],
    )
    .await;

    let reader = PgRetentionScanReader::new(pool.clone());
    let observed = reader
        .first_observed_at(artifact, &["cve-a".to_string()])
        .await
        .expect("first_observed_at");
    assert_eq!(
        observed,
        vec![("cve-a".to_string(), now - Duration::days(30))]
    );

    cleanup(&pool, repo_id).await;
}

/// An id with no row is **absent**, not defaulted. "We have no record of
/// ever seeing this" and "we first saw it at the epoch" are opposite
/// answers, and a sentinel would make the second one up.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_id_never_observed_is_absent_rather_than_defaulted() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());
    seed_scan(
        &pool,
        artifact,
        now - Duration::days(5),
        &[("CVE-A", "osv", None)],
    )
    .await;

    let reader = PgRetentionScanReader::new(pool.clone());
    let observed = reader
        .first_observed_at(artifact, &["cve-a".to_string(), "cve-unknown".to_string()])
        .await
        .expect("first_observed_at");
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].0, "cve-a");

    cleanup(&pool, repo_id).await;
}

/// The read answers only about the ids it was handed. This is the whole
/// safety argument for its history-wide scope: the caller takes those ids
/// from the artifact's LAST scan, so a vulnerability a later scan no
/// longer reports has history in the table that nothing asks about.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_retracted_vulnerabilitys_history_is_never_returned() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());

    // An ancient finding the latest scan no longer reports, plus the
    // current one.
    seed_scan(
        &pool,
        artifact,
        now - Duration::days(400),
        &[("CVE-RETRACTED", "trivy", None)],
    )
    .await;
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(1),
        &[("CVE-CURRENT", "trivy", None)],
    )
    .await;

    let reader = PgRetentionScanReader::new(pool.clone());
    let findings = reader
        .list_findings_for_artifact(artifact)
        .await
        .expect("list findings");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vulnerability_id, "CVE-CURRENT");

    // The ids the use case would ask about are exactly the last scan's.
    let ids: Vec<String> = findings
        .iter()
        .map(|f| f.vulnerability_id.to_ascii_lowercase())
        .collect();
    let observed = reader
        .first_observed_at(artifact, &ids)
        .await
        .expect("first_observed_at");
    assert_eq!(
        observed,
        vec![("cve-current".to_string(), now - Duration::hours(1))],
        "the 400-day-old retracted finding must not date this artifact"
    );

    // And the resolved anchor is an hour old, so a seven-day grace
    // period does not fire.
    let anchor = resolve_finding_age_anchor(&findings, &observed).expect("anchor");
    assert_eq!(anchor.known_since, now - Duration::hours(1));
    assert_eq!(anchor.source, FindingAgeAnchorSource::FirstObservation);
    assert!(
        !hort_domain::retention::matches_bool(
            &PolicyPredicate::HasFindingDetectedFor(7 * 24 * 3600),
            &hort_domain::retention::EvaluationInputs {
                now,
                created_at: now - Duration::days(500),
                last_downloaded_at: None,
                keep_rank: None,
                tag_targeted: false,
                findings: &findings,
                finding_age_anchor: Some(anchor),
                latest_scan_at: now - Duration::hours(1),
            },
        ),
        "known for an hour, whatever the retracted finding's history says"
    );

    cleanup(&pool, repo_id).await;
}

/// Case-insensitive, matching the cross-backend finding merge's
/// vulnerability identity: one feed spelling `ghsa-…` and another
/// `GHSA-…` are one vulnerability, and an earlier observation under the
/// other spelling is still an observation.
#[tokio::test]
#[serial(hort_pg_db)]
async fn two_spellings_of_one_advisory_collapse_to_the_earliest() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());

    seed_scan(
        &pool,
        artifact,
        now - Duration::days(20),
        &[("GHSA-Abcd-Efgh", "osv", None)],
    )
    .await;
    seed_scan(
        &pool,
        artifact,
        now - Duration::days(2),
        &[("ghsa-abcd-efgh", "trivy", None)],
    )
    .await;

    let reader = PgRetentionScanReader::new(pool.clone());
    let observed = reader
        .first_observed_at(artifact, &["GHSA-ABCD-EFGH".to_string()])
        .await
        .expect("first_observed_at");
    assert_eq!(
        observed,
        vec![("ghsa-abcd-efgh".to_string(), now - Duration::days(20))],
        "one vulnerability, one first observation, lowercased key"
    );

    cleanup(&pool, repo_id).await;
}

/// No ids ⇒ no query and no rows. An unbounded `= ANY('{}')` would scan
/// the artifact's whole findings history to return nothing.
#[tokio::test]
#[serial(hort_pg_db)]
async fn no_ids_returns_nothing() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());
    seed_scan(
        &pool,
        artifact,
        now - Duration::days(5),
        &[("CVE-A", "osv", None)],
    )
    .await;

    let reader = PgRetentionScanReader::new(pool.clone());
    assert!(reader
        .first_observed_at(artifact, &[])
        .await
        .expect("first_observed_at")
        .is_empty());

    cleanup(&pool, repo_id).await;
}

/// The publication date survives the projection round-trip, and the
/// resolved anchor prefers it over our own much later observation — the
/// whole point of persisting it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_publication_date_round_trips_and_anchors_the_grace_period() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());
    let published = now - Duration::days(60);

    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(1),
        &[("CVE-A", "osv", Some(published))],
    )
    .await;

    let reader = PgRetentionScanReader::new(pool.clone());
    let findings = reader
        .list_findings_for_artifact(artifact)
        .await
        .expect("list findings");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].advisory_published_at, Some(published));

    let observed = reader
        .first_observed_at(artifact, &["cve-a".to_string()])
        .await
        .expect("first_observed_at");
    let anchor = resolve_finding_age_anchor(&findings, &observed).expect("anchor");
    assert_eq!(anchor.known_since, published);
    assert_eq!(
        anchor.source,
        FindingAgeAnchorSource::AdvisoryPublication("osv".to_string())
    );

    cleanup(&pool, repo_id).await;
}

/// A row written before migration 034 reads back `None` — the column is
/// nullable with no default and deliberately not backfilled, because
/// nothing in this schema can derive an advisory's publication date. The
/// anchor then falls to our own first observation, which is later and so
/// the non-deleting reading.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_row_without_a_publication_date_falls_back_to_first_observation() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());

    seed_scan(
        &pool,
        artifact,
        now - Duration::days(9),
        &[("CVE-A", "osv", None)],
    )
    .await;
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(1),
        &[("CVE-A", "osv", None)],
    )
    .await;

    let reader = PgRetentionScanReader::new(pool.clone());
    let findings = reader
        .list_findings_for_artifact(artifact)
        .await
        .expect("list findings");
    assert_eq!(findings[0].advisory_published_at, None);
    let observed = reader
        .first_observed_at(artifact, &["cve-a".to_string()])
        .await
        .expect("first_observed_at");
    let anchor = resolve_finding_age_anchor(&findings, &observed).expect("anchor");
    assert_eq!(anchor.known_since, now - Duration::days(9));
    assert_eq!(anchor.source, FindingAgeAnchorSource::FirstObservation);

    cleanup(&pool, repo_id).await;
}

/// Two backends disagree on the same vulnerability: the earliest date
/// wins and the provenance names the backend it came from. Both rows
/// coexist in the projection because `source_scanner` is part of the
/// primary key.
#[tokio::test]
#[serial(hort_pg_db)]
async fn disagreeing_backends_resolve_to_the_earliest_with_its_provenance() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo_id).await;
    let now = truncate_us(Utc::now());
    let nvd_date = now - Duration::days(50);
    let osv_entry_date = now - Duration::days(44);

    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(1),
        &[
            ("CVE-A", "osv", Some(osv_entry_date)),
            ("CVE-A", "trivy", Some(nvd_date)),
        ],
    )
    .await;

    let reader = PgRetentionScanReader::new(pool.clone());
    let findings = reader
        .list_findings_for_artifact(artifact)
        .await
        .expect("list findings");
    assert_eq!(
        findings.len(),
        2,
        "both backends' rows are in the projection"
    );

    let anchor = resolve_finding_age_anchor(&findings, &[]).expect("anchor");
    assert_eq!(anchor.known_since, nvd_date);
    assert_eq!(
        anchor.source,
        FindingAgeAnchorSource::AdvisoryPublication("trivy".to_string()),
        "a feed dating systematically early has to be diagnosable"
    );

    cleanup(&pool, repo_id).await;
}
