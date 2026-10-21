//! `composite_scan_observations` Postgres adapter integration tests
//! (migration 032, ADR 0064 D6).
//!
//! What the table has to do, and what each test pins:
//!
//! 1. **Round-trip** — every column the promotion query reads survives
//!    a write and a read, including the two decision columns and the
//!    acquisition cost.
//! 2. **Replaced, not appended** — a second assessment of the same
//!    manifest overwrites its row. The whole point of keying on the
//!    artifact is that the table describes the estate's *current*
//!    state with no retention story to need.
//! 3. **The row leaves with its artifact** — `ON DELETE CASCADE`, so a
//!    purge does not leave a verdict behind about something that is
//!    gone.
//! 4. **The caps are the column's, not the producer's** — the
//!    migration's CHECKs restate the domain's bounds, so a writer that
//!    bypassed `validate` still cannot write an unbounded list.
//!
//! Every test gates on `DATABASE_URL` and early-returns without one,
//! and carries the workspace-wide `#[serial(hort_pg_db)]` key.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test composite_scan_observations
//! ```

#![allow(clippy::expect_used)]

use std::env;

use chrono::{DateTime, TimeZone, Utc};
use serial_test::serial;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_adapters_postgres::composite_scan_observations::PgCompositeScanObservationRepository;
use hort_domain::events::SeveritySummary;
use hort_domain::ports::composite_scan_observation::{
    AcquisitionCost, CompositeAssessment, CompositeScanObservation,
    CompositeScanObservationRepository, GateDecision, MAX_OBSERVED_VULNERABILITY_IDS,
};
use hort_domain::types::ContentHash;

async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-cso-{}", id.simple());
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $3,
               'oci'::repository_format,
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

/// Seed a manifest artifact and return `(artifact_id, its sha256)`.
async fn seed_artifact(pool: &PgPool, repo: Uuid) -> (Uuid, ContentHash) {
    let id = Uuid::new_v4();
    let key = id.simple().to_string();
    let sha256 = format!("{key}{key}");
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key
           ) VALUES (
               $1, $2, 'library/nginx', 'library/nginx', '1.27', $3,
               512, $4, 'application/vnd.oci.image.manifest.v1+json', $4
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(format!("manifests/sha256:{sha256}"))
    .bind(&sha256)
    .execute(pool)
    .await
    .expect("seed artifact");
    (id, sha256.parse().expect("a sha256 hex digest"))
}

fn at(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0)
        .single()
        .expect("a valid instant")
}

/// An assessed observation with every column populated to something
/// distinguishable, so a mis-bound parameter shows up as a mismatch
/// rather than as a coincidence.
fn assessed(
    artifact_id: Uuid,
    repository_id: Uuid,
    digest: ContentHash,
) -> CompositeScanObservation {
    CompositeScanObservation {
        artifact_id,
        repository_id,
        manifest_digest: digest,
        scanner: Some("trivy".to_string()),
        observed_at: at(1_700_000_000),
        assessment: CompositeAssessment::Assessed,
        reason: None,
        cost: AcquisitionCost {
            already_present: 1,
            fetched: 2,
            fetched_bytes: 3_145_728,
        },
        severity_summary: SeveritySummary {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
            negligible: 5,
        },
        finding_count: 15,
        distinct_vulnerability_count: 3,
        vulnerability_ids: vec![
            "CVE-2024-1".to_string(),
            "CVE-2024-2".to_string(),
            "CVE-2024-3".to_string(),
        ],
        composite_findings_decision: Some(GateDecision::Reject),
        primary_findings_decision: GateDecision::Clean,
    }
}

/// Every column the promotion query reads survives the round trip.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_observation_round_trips_through_the_projection() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let (artifact_id, digest) = seed_artifact(&pool, repo_id).await;
    let repo = PgCompositeScanObservationRepository::new(pool.clone());

    let written = assessed(artifact_id, repo_id, digest);
    repo.record(&written).await.expect("record");

    let read = repo
        .find_by_artifact(artifact_id)
        .await
        .expect("find")
        .expect("the row that was just written");
    assert_eq!(read, written);
}

/// The two decision columns are named for the **finding set** the gate
/// decided over, and each holds its own side.
///
/// Three things in one test, because they only mean something together:
/// the schema carries exactly these names, the pre-rename names are
/// gone, and a row whose two sides differ comes back out of the two
/// columns differing in the same direction. The last one is what a
/// mis-bound parameter breaks — two columns of one value round-trip
/// through `assert_eq!(read, written)` whenever the fixture's two sides
/// happen to agree, and the promotion question is exactly the question
/// about when they do not.
///
/// Why the old names are asserted *absent*: a half-done rename —
/// migration renamed, adapter not, or either against a database
/// migrated from an older checkout of 032 — is the failure mode worth
/// naming, and `primary_decision` reading `clean` over an abstained run
/// is what the rename exists to stop an operator believing.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_decision_columns_name_their_finding_set_and_hold_their_own_side() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let (artifact_id, digest) = seed_artifact(&pool, repo_id).await;
    let repo = PgCompositeScanObservationRepository::new(pool.clone());

    // The fixture's two sides deliberately disagree: `reject` over the
    // composite findings, `clean` over the primary ones.
    let written = assessed(artifact_id, repo_id, digest);
    assert_ne!(
        written.composite_findings_decision,
        Some(written.primary_findings_decision),
        "the fixture has to disagree or this test cannot tell the columns apart"
    );
    repo.record(&written).await.expect("record");

    let row = sqlx::query(
        "SELECT composite_findings_decision, primary_findings_decision
           FROM composite_scan_observations
          WHERE artifact_id = $1",
    )
    .bind(artifact_id)
    .fetch_one(&pool)
    .await
    .expect("the renamed columns exist and hold the written row");
    assert_eq!(
        row.get::<Option<String>, _>("composite_findings_decision"),
        Some("reject".to_string())
    );
    assert_eq!(
        row.get::<String, _>("primary_findings_decision"),
        "clean".to_string()
    );

    // And the pre-rename spellings are not still there beside them.
    let lingering: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'composite_scan_observations'
            AND column_name IN ('composite_decision', 'primary_decision')",
    )
    .fetch_all(&pool)
    .await
    .expect("read the column list");
    assert!(
        lingering.is_empty(),
        "the pre-rename decision columns are still in the schema: {lingering:?}"
    );
}

/// An artifact nobody assessed has no row, and the read says so rather
/// than inventing a clean one.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_unassessed_artifact_has_no_observation() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let (artifact_id, _digest) = seed_artifact(&pool, repo_id).await;
    let repo = PgCompositeScanObservationRepository::new(pool.clone());

    assert!(repo
        .find_by_artifact(artifact_id)
        .await
        .expect("find")
        .is_none());
}

/// Each of the four outcomes is accepted, and the three that composed
/// nothing carry their reason with a NULL counterfactual — the
/// `composite_findings_decision IS NULL OR assessment = 'assessed'` CHECK is the
/// column's restatement of the domain rule.
#[tokio::test]
#[serial(hort_pg_db)]
async fn every_outcome_is_storable_and_only_an_assessment_carries_a_counterfactual() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let repo = PgCompositeScanObservationRepository::new(pool.clone());

    for (assessment, reason) in [
        (CompositeAssessment::Assessed, None),
        (
            CompositeAssessment::NothingToCompose,
            Some("an image index binds references, not a filesystem".to_string()),
        ),
        (
            CompositeAssessment::DeterministicRefusal,
            Some("the manifest's bytes are not a manifest".to_string()),
        ),
        (
            CompositeAssessment::TransientRefusal,
            Some("the store did not answer for the image config".to_string()),
        ),
    ] {
        let (artifact_id, digest) = seed_artifact(&pool, repo_id).await;
        let mut observation = assessed(artifact_id, repo_id, digest);
        observation.assessment = assessment;
        observation.reason = reason.clone();
        if assessment != CompositeAssessment::Assessed {
            observation.composite_findings_decision = None;
            observation.scanner = None;
            observation.severity_summary = SeveritySummary {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 0,
            };
            observation.finding_count = 0;
            observation.distinct_vulnerability_count = 0;
            observation.vulnerability_ids = Vec::new();
        }
        repo.record(&observation).await.expect("record");

        let read = repo
            .find_by_artifact(artifact_id)
            .await
            .expect("find")
            .expect("the row");
        assert_eq!(read.assessment, assessment);
        assert_eq!(read.reason, reason);
        assert_eq!(
            read.composite_findings_decision.is_some(),
            assessment == CompositeAssessment::Assessed
        );
        // The primary axis's conclusion is recorded on every arm: "of
        // the manifests we could not compose, what were they?" is a
        // question too.
        assert_eq!(read.primary_findings_decision, GateDecision::Clean);
    }
}

/// A second assessment of the same manifest replaces its row. One row
/// per artifact is what makes the table bounded by a population the
/// artifact table already bounds.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_second_assessment_replaces_the_row_rather_than_adding_one() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let (artifact_id, digest) = seed_artifact(&pool, repo_id).await;
    let repo = PgCompositeScanObservationRepository::new(pool.clone());

    repo.record(&assessed(artifact_id, repo_id, digest.clone()))
        .await
        .expect("first assessment");

    let mut second = assessed(artifact_id, repo_id, digest);
    second.observed_at = at(1_700_000_600);
    second.composite_findings_decision = Some(GateDecision::Clean);
    second.primary_findings_decision = GateDecision::Clean;
    second.finding_count = 0;
    second.distinct_vulnerability_count = 0;
    second.vulnerability_ids = Vec::new();
    second.severity_summary = SeveritySummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        negligible: 0,
    };
    second.cost = AcquisitionCost::default();
    repo.record(&second).await.expect("second assessment");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM composite_scan_observations WHERE artifact_id = $1",
    )
    .bind(artifact_id)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(count, 1, "the assessment replaced, it did not accumulate");

    let read = repo
        .find_by_artifact(artifact_id)
        .await
        .expect("find")
        .expect("the row");
    assert_eq!(read, second, "the newer assessment is what the row says");
}

/// The row goes away with its artifact. A verdict about something that
/// no longer exists is worse than no verdict: the promotion query would
/// count it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_row_goes_away_with_its_artifact() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let (artifact_id, digest) = seed_artifact(&pool, repo_id).await;
    let repo = PgCompositeScanObservationRepository::new(pool.clone());
    repo.record(&assessed(artifact_id, repo_id, digest))
        .await
        .expect("record");

    sqlx::query("DELETE FROM public.artifacts WHERE id = $1")
        .bind(artifact_id)
        .execute(&pool)
        .await
        .expect("delete the artifact");

    assert!(repo
        .find_by_artifact(artifact_id)
        .await
        .expect("find")
        .is_none());
}

/// The full stored list at the cap round-trips, and the counts stay
/// exact above it — the cap is on the column, not on what the row
/// claims the composition found.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_capped_id_list_stores_with_exact_counts() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let (artifact_id, digest) = seed_artifact(&pool, repo_id).await;
    let repo = PgCompositeScanObservationRepository::new(pool.clone());

    let mut observation = assessed(artifact_id, repo_id, digest);
    observation.vulnerability_ids = (0..MAX_OBSERVED_VULNERABILITY_IDS)
        .map(|i| format!("CVE-2024-{i:05}"))
        .collect();
    observation.distinct_vulnerability_count = 4_000;
    observation.finding_count = 4_200;
    repo.record(&observation).await.expect("record");

    let read = repo
        .find_by_artifact(artifact_id)
        .await
        .expect("find")
        .expect("the row");
    assert_eq!(read.vulnerability_ids.len(), MAX_OBSERVED_VULNERABILITY_IDS);
    assert_eq!(read.distinct_vulnerability_count, 4_000);
    assert_eq!(read.finding_count, 4_200);
}

/// The caps belong to the column. A writer that bypassed the domain's
/// `validate` — a repair script, a future adapter — still cannot leave
/// an unbounded list or a counterfactual on a refusal behind.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_columns_refuse_what_the_domain_refuses() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let (artifact_id, digest) = seed_artifact(&pool, repo_id).await;

    let over_cap: Vec<String> = (0..MAX_OBSERVED_VULNERABILITY_IDS + 1)
        .map(|i| format!("CVE-{i}"))
        .collect();
    let err = insert_raw(
        &pool,
        artifact_id,
        repo_id,
        &digest,
        "assessed",
        Some("reject"),
        &over_cap,
        i64::try_from(over_cap.len()).expect("fits"),
    )
    .await
    .expect_err("an unbounded id list");
    assert!(format!("{err}").contains("ids_bounded"), "{err}");

    let err = insert_raw(
        &pool,
        artifact_id,
        repo_id,
        &digest,
        "transient_refusal",
        Some("reject"),
        &[],
        0,
    )
    .await
    .expect_err("a counterfactual on a refusal");
    assert!(
        format!("{err}").contains("counterfactual_needs_assessment"),
        "{err}"
    );

    let err = insert_raw(
        &pool,
        artifact_id,
        repo_id,
        &digest,
        "composed",
        None,
        &[],
        0,
    )
    .await
    .expect_err("an outcome outside the closed set");
    assert!(format!("{err}").contains("assessment_known"), "{err}");

    // The stored list is a truncation of the count, never larger.
    let err = insert_raw(
        &pool,
        artifact_id,
        repo_id,
        &digest,
        "assessed",
        Some("clean"),
        &["CVE-1".to_string(), "CVE-2".to_string()],
        1,
    )
    .await
    .expect_err("more stored ids than the count claims");
    assert!(format!("{err}").contains("ids_are_a_truncation"), "{err}");
}

/// Bypass the adapter and bind the columns directly, so the CHECKs are
/// what answers rather than `CompositeScanObservation::validate`.
#[allow(clippy::too_many_arguments)]
async fn insert_raw(
    pool: &PgPool,
    artifact_id: Uuid,
    repository_id: Uuid,
    digest: &ContentHash,
    assessment: &str,
    composite_findings_decision: Option<&str>,
    vulnerability_ids: &[String],
    distinct_count: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO composite_scan_observations (
            artifact_id, repository_id, manifest_digest, observed_at, assessment,
            already_present, fetched, fetched_bytes,
            severity_critical, severity_high, severity_medium, severity_low,
            severity_negligible,
            finding_count, distinct_vulnerability_count, vulnerability_ids,
            composite_findings_decision, primary_findings_decision
        ) VALUES (
            $1, $2, $3, now(), $4,
            0, 0, 0,
            0, 0, 0, 0, 0,
            $5, $6, $7,
            $8, 'clean'
        )
        ON CONFLICT (artifact_id) DO UPDATE SET assessment = EXCLUDED.assessment
        "#,
    )
    .bind(artifact_id)
    .bind(repository_id)
    .bind(digest.to_string())
    .bind(assessment)
    .bind(distinct_count.max(i64::try_from(vulnerability_ids.len()).expect("fits")))
    .bind(distinct_count)
    .bind(vulnerability_ids)
    .bind(composite_findings_decision)
    .execute(pool)
    .await
    .map(|_| ())
}

/// A count outside the `u32` range is a row no writer of this table
/// produced, and the decoder refuses it rather than clamping — a
/// clamped count is a wrong answer to the promotion question that reads
/// as a right one.
///
/// Reached by dropping the column CHECK in this test's own throwaway
/// database, because that CHECK is what makes the value unreachable
/// through every supported path. The constraint is the first line of
/// defence; this asserts the second.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_count_outside_the_u32_range_is_refused_rather_than_clamped() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let (artifact_id, digest) = seed_artifact(&pool, repo_id).await;
    let repo = PgCompositeScanObservationRepository::new(pool.clone());
    repo.record(&assessed(artifact_id, repo_id, digest))
        .await
        .expect("record");

    sqlx::query(
        "ALTER TABLE composite_scan_observations
             DROP CONSTRAINT composite_scan_observations_counts_in_u32",
    )
    .execute(&pool)
    .await
    .expect("drop the range CHECK in this test's own database");
    sqlx::query("UPDATE composite_scan_observations SET finding_count = $1 WHERE artifact_id = $2")
        .bind(i64::from(u32::MAX) + 1)
        .bind(artifact_id)
        .execute(&pool)
        .await
        .expect("write a count the CHECK would have refused");

    let err = repo
        .find_by_artifact(artifact_id)
        .await
        .expect_err("a count outside the range the column permits");
    let msg = format!("{err}");
    assert!(msg.contains("finding_count"), "{msg}");
    assert!(msg.contains("u32 range"), "{msg}");
}

/// The foreign key on `repository_id` is indexed, because the cascade
/// that follows a repository delete would otherwise sequentially scan
/// this table — and so would the per-repository promotion query.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_repository_foreign_key_is_indexed() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let indexed: bool = sqlx::query(
        "SELECT EXISTS (
             SELECT 1 FROM pg_indexes
              WHERE schemaname = 'public'
                AND tablename = 'composite_scan_observations'
                AND indexdef LIKE '%(repository_id)%'
         )",
    )
    .fetch_one(&pool)
    .await
    .expect("index lookup")
    .get(0);
    assert!(indexed, "composite_scan_observations (repository_id)");
}
