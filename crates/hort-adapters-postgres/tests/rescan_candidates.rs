//! `PgRescanCandidatesRepository` integration tests
//! against the `artifacts` / `policy_projections` / `jobs` schema from
//! migrations 003 + 005 + 009.
//!
//! `DATABASE_URL`-gated per the project convention. When unset, every
//! test early-returns `Ok` so dev environments without a database keep
//! the suite green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test rescan_candidates
//! ```
//!
//! Coverage matrix (mirrors the eligibility predicate):
//!
//! - `select_eligible_returns_never_scanned_released_artifact`
//! - `select_eligible_skips_recently_scanned_within_interval`
//! - `select_eligible_returns_artifact_scanned_before_interval`
//! - `select_eligible_skips_zero_interval_disabled_policy`
//! - `select_eligible_skips_quarantined_artifact`
//! - `select_eligible_skips_rejected_artifact`
//! - `select_eligible_skips_artifact_with_pending_scan_job`
//! - `select_eligible_returns_artifact_with_completed_scan_job_only`
//! - `select_eligible_returns_null_quarantine_artifact`
//! - `select_eligible_returns_null_quarantine_no_policy_artifact`
//!
//! `select_stranded` coverage matrix — the stranded-scan recovery ADR
//! 0007's retry-exhaustion split introduced, its later widening to
//! artifacts with no scan job at all, and its "A reached verdict
//! supersedes an absent one" amendment. Mirrors the predicate:
//! `quarantine_status IN ('quarantined', 'scan_indeterminate')` +
//! (most-recent `kind='scan'` job `status='failed'` OR no `kind='scan'`
//! job at all OR — for `scan_indeterminate` only — a most-recent job
//! requested longer ago than the resolved rescan interval) + resolved
//! policy actually scans:
//!
//! - `select_stranded_returns_quarantined_artifact_with_failed_last_scan`
//! - `select_stranded_returns_quarantined_artifact_with_no_scan_job_under_scanning_policy` (#115)
//! - `select_stranded_skips_quarantined_artifact_with_no_scan_job_under_scan_waived_policy` (#115)
//! - `select_stranded_skips_quarantined_artifact_with_pending_last_scan`
//! - `select_stranded_skips_released_artifact_even_with_failed_scan`
//! - `select_stranded_returns_scan_indeterminate_artifact_with_failed_last_scan`
//! - `select_stranded_returns_scan_indeterminate_artifact_with_no_scan_job_under_scanning_policy`
//! - `select_stranded_skips_scan_indeterminate_artifact_with_a_fresh_completed_scan`
//!   (a scan that answered "nothing analysable" completes its row, so
//!   the sweep declines the artifact until its rescan interval elapses
//!   — the default-interval half of the absent-verdict cooldown, and it
//!   carries its own flip-the-status counter-assertion)
//! - `select_stranded_skips_scan_indeterminate_artifact_under_scan_waived_policy`
//! - `select_stranded_skips_soft_deleted_scan_indeterminate_artifact`
//! - `select_stranded_skips_rejected_artifact_even_with_failed_scan`
//! - `select_stranded_skips_artifact_with_newer_in_flight_job_despite_older_failed_job`
//!
//! The absent-verdict arm, which is the existing-estate cutover's first
//! two populations — a hold whose last scan job is `completed` because
//! every backend ran and reported nothing to analyse:
//!
//! - `select_stranded_returns_a_scan_indeterminate_artifact_whose_no_verdict_job_completed`
//! - `select_stranded_skips_a_scan_indeterminate_artifact_re_asked_within_the_interval`
//! - `select_stranded_absent_verdict_arm_honours_the_resolved_interval`
//! - `select_stranded_absent_verdict_arm_reads_a_zero_interval_as_the_default`
//! - `select_stranded_absent_verdict_arm_still_honours_a_scan_waiver`
//! - `select_stranded_still_returns_a_failed_scan_hold_with_no_cooldown`
//! - `select_stranded_skips_a_quarantined_artifact_with_a_completed_job_however_old`
//!
//! `select_composite_unassessed` coverage matrix — the cutover's third
//! population: a live OCI image manifest with no composite assessment on
//! record:
//!
//! - `select_composite_unassessed_returns_a_released_manifest_with_no_observation`
//! - `select_composite_unassessed_returns_a_null_status_manifest`
//! - `select_composite_unassessed_returns_a_manifest_with_no_stored_media_type`
//! - `select_composite_unassessed_skips_a_manifest_with_any_recorded_observation`
//! - `select_composite_unassessed_skips_an_image_index`
//! - `select_composite_unassessed_skips_a_non_manifest_artifact`
//! - `select_composite_unassessed_skips_a_manifest_that_is_not_live`
//! - `select_composite_unassessed_skips_a_manifest_under_a_scan_waived_policy`
//! - `select_composite_unassessed_skips_a_manifest_with_an_in_flight_scan`
//! - `select_composite_unassessed_spends_no_batch_slot_on_a_soft_deleted_manifest`
//! - `select_composite_unassessed_is_bounded_by_the_batch_size`
//! - `select_composite_unassessed_errs_when_the_observation_projection_is_unreadable`
//!
//! Soft delete, which both predicates share (`a.deleted_at IS NULL`):
//!
//! - `select_eligible_skips_soft_deleted_artifact`
//! - `select_eligible_spends_no_batch_slot_on_a_soft_deleted_artifact`
//! - `select_stranded_skips_soft_deleted_artifact`
//! - `select_stranded_spends_no_batch_slot_on_a_soft_deleted_artifact`
//! - `both_sweeps_still_return_a_live_artifact`
//!
//! Every test here carries `#[serial(hort_pg_db)]`, the workspace-wide
//! DB-test parallel-safety key (CLAUDE.md → Test Coverage Tiers →
//! DB-backed test isolation), and that key is the file's **only**
//! serialization. Do not add a file-local mutex beside it: two
//! independent orders do not compose into one, so a test taking only
//! the mutex and a test taking only the key run concurrently. What
//! needs ordering here is the policy read — a Global-scoped
//! `ScanPolicy` created by a sibling shadows the `WHERE NOT EXISTS
//! Repository` fallback these tests resolve through — and the key
//! covers it.

#![allow(clippy::expect_used)]

use std::env;

use chrono::{Duration as ChronoDuration, Utc};
use serde_json::json;
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::rescan_candidates::PgRescanCandidatesRepository;
use hort_domain::ports::rescan_candidates::RescanCandidatesRepository;

/// Connect as the migration superuser; run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

/// Seed a minimal repository row with a unique key/name and return its id.
async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-rescan-{}", id.simple());
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
    .expect("seed repository row");
    id
}

/// Seed an artifact row with the requested `quarantine_status` and
/// `last_scan_at`. A `quarantine_status` of `None` writes SQL NULL —
/// the permissive-default terminal state. Returns the artifact id.
async fn seed_artifact(
    pool: &PgPool,
    repo: Uuid,
    quarantine_status: Option<&str>,
    last_scan_at: Option<chrono::DateTime<Utc>>,
) -> Uuid {
    let id = Uuid::new_v4();
    let key = id.simple().to_string();
    let sha256 = format!("{key}{key}");
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key,
               quarantine_status, last_scan_at
           ) VALUES (
               $1, $2, 'rescan-it', 'rescan-it', '0.0.0', $3,
               0, $4, 'application/octet-stream', $4,
               $5, $6
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(format!("simple/rescan-it/{key}.tar.gz"))
    .bind(&sha256)
    .bind(quarantine_status)
    .bind(last_scan_at)
    .execute(pool)
    .await
    .expect("seed artifact row");
    id
}

/// Seed a non-archived repository-scoped policy with the requested
/// `rescan_interval_hours`. Each policy gets a unique `name` and
/// `policy_id` so the UNIQUE constraint never collides with a sibling
/// binary's row.
async fn seed_repo_scoped_policy(pool: &PgPool, repo_id: Uuid, rescan_interval_hours: i32) -> Uuid {
    let policy_id = Uuid::new_v4();
    let name = format!("it-rescan-policy-{}", policy_id.simple());
    let scope = json!({ "Repository": repo_id });
    sqlx::query(
        r#"INSERT INTO public.policy_projections (
               policy_id, name, scope, severity_threshold,
               rescan_interval_hours, quarantine_duration_secs,
               require_approval, archived,
               stream_version
           ) VALUES (
               $1, $2, $3, 'high',
               $4, 86400,
               false, false,
               1
           )"#,
    )
    .bind(policy_id)
    .bind(&name)
    .bind(&scope)
    .bind(rescan_interval_hours)
    .execute(pool)
    .await
    .expect("seed repo-scoped policy_projections row");
    policy_id
}

/// Seed a non-archived repository-scoped policy with `scan_backends: []`
/// — the operator's explicit ScanWaived opt-out. Used by the #115 item2
/// `select_stranded` scan-policy-aware guard tests: a job-less (or
/// failed-job) artifact under this policy must NOT be treated as
/// stranded, in either hold — see
/// `crates/hort-adapters-postgres/src/rescan_candidates.rs`'s
/// `select_stranded` doc comment.
async fn seed_repo_scoped_scan_waived_policy(pool: &PgPool, repo_id: Uuid) -> Uuid {
    let policy_id = Uuid::new_v4();
    let name = format!("it-rescan-waived-policy-{}", policy_id.simple());
    let scope = json!({ "Repository": repo_id });
    sqlx::query(
        r#"INSERT INTO public.policy_projections (
               policy_id, name, scope, severity_threshold,
               rescan_interval_hours, quarantine_duration_secs,
               require_approval, archived, scan_backends,
               stream_version
           ) VALUES (
               $1, $2, $3, 'high',
               24, 86400,
               false, false, ARRAY[]::text[],
               1
           )"#,
    )
    .bind(policy_id)
    .bind(&name)
    .bind(&scope)
    .execute(pool)
    .await
    .expect("seed scan-waived repo-scoped policy_projections row");
    policy_id
}

/// Seed a `kind='scan'` `jobs` row with the requested status. Used to
/// verify the NOT EXISTS clause around in-flight scans.
async fn seed_scan_job(pool: &PgPool, repo_id: Uuid, artifact_id: Uuid, status: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO public.jobs \
            (kind, artifact_id, repository_id, content_hash, format, priority, status) \
         VALUES ('scan', $1, $2, $3, 'pypi', 0, $4) \
         RETURNING id",
    )
    .bind(artifact_id)
    .bind(repo_id)
    .bind(format!("{}{}", artifact_id.simple(), artifact_id.simple()))
    .bind(status)
    .fetch_one(pool)
    .await
    .expect("seed scan job row");
    id
}

// =====================================================================
// Helper — fetch only the candidate rows whose artifact_id is one of
// the provided ids. Filters out anything sibling-binary or sibling-test
// might have left behind.
// =====================================================================
fn filter_to<'a>(
    rows: &'a [hort_domain::ports::rescan_candidates::RescanCandidate],
    ids: &[Uuid],
) -> Vec<&'a hort_domain::ports::rescan_candidates::RescanCandidate> {
    rows.iter()
        .filter(|c| ids.contains(&c.artifact_id))
        .collect()
}

// =====================================================================
// (a) Never-scanned, released artifact → returned
// =====================================================================

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_returns_never_scanned_released_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let artifact = seed_artifact(&pool, repo, Some("released"), None).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let now = Utc::now();
    let rows = port
        .select_eligible(1000, now)
        .await
        .expect("select_eligible Ok");

    let ours = filter_to(&rows, &[artifact]);
    assert_eq!(
        ours.len(),
        1,
        "never-scanned released artifact must be returned"
    );
    assert_eq!(ours[0].repository_id, repo);
    assert_eq!(ours[0].format, "pypi");
    assert_eq!(ours[0].rescan_interval_hours, 24);
}

// =====================================================================
// (b) Recently scanned (now - 1h, interval 24h) → NOT returned
// =====================================================================

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_skips_recently_scanned_within_interval() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let now = Utc::now();
    let last_scan = now - ChronoDuration::hours(1);
    let artifact = seed_artifact(&pool, repo, Some("released"), Some(last_scan)).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_eligible(1000, now)
        .await
        .expect("select_eligible Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "artifact scanned within the interval must NOT be returned"
    );
}

// =====================================================================
// (c) Scanned long ago (now - 30h, interval 24h) → returned
// =====================================================================

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_returns_artifact_scanned_before_interval() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let now = Utc::now();
    let last_scan = now - ChronoDuration::hours(30);
    let artifact = seed_artifact(&pool, repo, Some("released"), Some(last_scan)).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_eligible(1000, now)
        .await
        .expect("select_eligible Ok");

    let ours = filter_to(&rows, &[artifact]);
    assert_eq!(
        ours.len(),
        1,
        "artifact past its rescan interval must be returned"
    );
}

// =====================================================================
// (d) rescan_interval_hours = 0 (disabled) → NOT returned
// =====================================================================

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_skips_zero_interval_disabled_policy() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 0).await;
    // last_scan_at NULL — would be eligible if the interval were > 0.
    let artifact = seed_artifact(&pool, repo, Some("released"), None).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_eligible(1000, Utc::now())
        .await
        .expect("select_eligible Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "rescan_interval_hours=0 must disable rescanning for the policy's artifacts"
    );
}

// =====================================================================
// (e) quarantine_status = 'quarantined' → NOT returned (sticky-rejection)
// =====================================================================

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_skips_quarantined_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined"), None).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_eligible(1000, Utc::now())
        .await
        .expect("select_eligible Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "quarantined artifact must NOT be returned (sticky-rejection invariant)"
    );
}

// =====================================================================
// (f) quarantine_status = 'rejected' → NOT returned (sticky-rejection)
// =====================================================================

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_skips_rejected_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let artifact = seed_artifact(&pool, repo, Some("rejected"), None).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_eligible(1000, Utc::now())
        .await
        .expect("select_eligible Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "rejected artifact must NOT be returned (sticky-rejection invariant)"
    );
}

// =====================================================================
// (g) Existing pending scan job → NOT returned (NOT EXISTS clause)
// =====================================================================

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_skips_artifact_with_pending_scan_job() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let artifact = seed_artifact(&pool, repo, Some("released"), None).await;
    let _existing = seed_scan_job(&pool, repo, artifact, "pending").await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_eligible(1000, Utc::now())
        .await
        .expect("select_eligible Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "artifact with a pending scan job must NOT be returned (NOT EXISTS clause)"
    );
}

// =====================================================================
// (h) Existing completed scan job (not active) → returned (SELECT-side OK)
// =====================================================================

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_returns_artifact_with_completed_scan_job_only() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let artifact = seed_artifact(&pool, repo, Some("released"), None).await;
    let _completed = seed_scan_job(&pool, repo, artifact, "completed").await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_eligible(1000, Utc::now())
        .await
        .expect("select_eligible Ok");

    let ours = filter_to(&rows, &[artifact]);
    assert_eq!(
        ours.len(),
        1,
        "completed (not active) scan job must NOT block re-eligibility \
         — the NOT EXISTS clause filters status IN ('pending','running') only",
    );
}

// =====================================================================
// (i) NULL quarantine_status + repo-scoped policy → returned.
//     The permissive-default terminal state (quarantine_status NULL)
//     is a live, downloadable state and must be cron-rescan-eligible.
//     Pre-fix the `= 'released'` filter excluded it.
// =====================================================================

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_returns_null_quarantine_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    // quarantine_status NULL — permissive-default terminal state.
    let artifact = seed_artifact(&pool, repo, None, None).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_eligible(1000, Utc::now())
        .await
        .expect("select_eligible Ok");

    let ours = filter_to(&rows, &[artifact]);
    assert_eq!(
        ours.len(),
        1,
        "never-scanned artifact with quarantine_status NULL must be returned"
    );
    assert_eq!(ours[0].rescan_interval_hours, 24);
}

// =====================================================================
// (j) NULL quarantine_status + NO policy → returned via the
//     DefaultPolicy fallback. This is the alpha-test scenario: an
//     out-of-the-box deployment with zero ScanPolicy rows. Pre-fix the
//     INNER JOIN dropped the no-policy row entirely; the LEFT JOIN
//     keeps it and `COALESCE(_, $3)` supplies the 24h default.
// =====================================================================

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_returns_null_quarantine_no_policy_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    // No policy seeded — resolution falls through to DefaultPolicy.
    let artifact = seed_artifact(&pool, repo, None, None).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_eligible(1000, Utc::now())
        .await
        .expect("select_eligible Ok");

    // The LEFT JOIN keeps a no-policy artifact; pre-fix the INNER JOIN
    // dropped it. `rescan_interval_hours` is intentionally NOT asserted
    // here — a Global ScanPolicy created by a sibling would shadow the
    // DefaultPolicy fallback, and `WHERE NOT EXISTS Repository` makes
    // that fallback global by construction. Test (i) pins the interval
    // deterministically via a repo-scoped policy instead.
    assert_eq!(
        filter_to(&rows, &[artifact]).len(),
        1,
        "never-scanned NULL-quarantine artifact with no policy must be \
         returned — DefaultPolicy fallback, not dropped by the join"
    );
}

// =====================================================================
// select_stranded — issue #6 stranded-scan recovery
// =====================================================================

/// Seed a `kind='scan'` `jobs` row with an explicit `created_at`, so
/// tests can construct a deterministic "most recent job" ordering across
/// multiple rows for the same artifact. Mirrors `seed_scan_job` but adds
/// the timestamp override.
async fn seed_scan_job_at(
    pool: &PgPool,
    repo_id: Uuid,
    artifact_id: Uuid,
    status: &str,
    created_at: chrono::DateTime<Utc>,
) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO public.jobs \
            (kind, artifact_id, repository_id, content_hash, format, priority, status, created_at, updated_at) \
         VALUES ('scan', $1, $2, $3, 'pypi', 0, $4, $5, $5) \
         RETURNING id",
    )
    .bind(artifact_id)
    .bind(repo_id)
    .bind(format!("{}{}", artifact_id.simple(), artifact_id.simple()))
    .bind(status)
    .bind(created_at)
    .fetch_one(pool)
    .await
    .expect("seed scan job row with explicit created_at");
    id
}

// ---------------------------------------------------------------------
// (a) Quarantined artifact, last (only) scan job failed → returned
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_returns_quarantined_artifact_with_failed_last_scan() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined"), None).await;
    let _job = seed_scan_job(&pool, repo, artifact, "failed").await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    let matched = filter_to(&rows, &[artifact]);
    assert_eq!(
        matched.len(),
        1,
        "quarantined artifact with a failed last scan must be returned"
    );
    assert_eq!(matched[0].repository_id, repo);
    assert_eq!(matched[0].format, "pypi");
}

// ---------------------------------------------------------------------
// (a2) Malformed `checksum_sha256` on an otherwise-matching row → Err
//      (defensive row-decode error path, shared by select_eligible and
//      select_stranded via the same content_hash_str.parse() closure)
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_errs_on_malformed_checksum() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined"), None).await;
    let _job = seed_scan_job(&pool, repo, artifact, "failed").await;
    // `character(64)` accepts any 64-byte string — not hex-validated at
    // the DB layer. `ContentHash::parse` is the only validator, so this
    // exercises the adapter's defensive decode-error path.
    sqlx::query("UPDATE public.artifacts SET checksum_sha256 = $1 WHERE id = $2")
        .bind("z".repeat(64))
        .bind(artifact)
        .execute(&pool)
        .await
        .expect("corrupt checksum_sha256 for the decode-error test");

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let err = port
        .select_stranded(1000, Utc::now())
        .await
        .expect_err("malformed checksum_sha256 must surface as an Err, not a silent skip");
    assert!(
        format!("{err}").contains("invalid content_hash"),
        "error should name the decode failure: {err}"
    );
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_errs_on_malformed_checksum() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let artifact = seed_artifact(&pool, repo, Some("released"), None).await;
    sqlx::query("UPDATE public.artifacts SET checksum_sha256 = $1 WHERE id = $2")
        .bind("z".repeat(64))
        .bind(artifact)
        .execute(&pool)
        .await
        .expect("corrupt checksum_sha256 for the decode-error test");

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let err = port
        .select_eligible(1000, Utc::now())
        .await
        .expect_err("malformed checksum_sha256 must surface as an Err, not a silent skip");
    assert!(
        format!("{err}").contains("invalid content_hash"),
        "error should name the decode failure: {err}"
    );
}

// ---------------------------------------------------------------------
// (b) Quarantined artifact, never scanned (no jobs row), under a
//     SCANNING policy → returned. #115 defect (a) cure: pre-widening,
//     a job-less quarantined artifact was invisible to both
//     `select_eligible` (requires `released`/`NULL`) and the OLD
//     `select_stranded` (required a *failed* job row, and a job-less
//     artifact has no job row at all) — permanently stranded with no
//     manual rescan surface to recover it. This is the exact seed-import
//     stranding scenario item1 stops at the source; this sweep recovers
//     rows already stranded that way before that fix.
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_returns_quarantined_artifact_with_no_scan_job_under_scanning_policy() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    // Explicit repo-scoped policy — default `scan_backends = ['trivy']`
    // (the column DEFAULT; `seed_repo_scoped_policy` does not override
    // it), i.e. scanning is active. Deterministic: unlike relying on the
    // DefaultPolicy no-policy fallback, this cannot be shadowed by a
    // sibling test binary's stray Global policy.
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined"), None).await;
    // No scan job seeded at all.

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    let matched = filter_to(&rows, &[artifact]);
    assert_eq!(
        matched.len(),
        1,
        "a quarantined artifact with no scan job history at all, under a \
         scanning policy, IS stranded and must be recovered (issue #115 \
         defect (a) cure — the widened LEFT JOIN LATERAL admits \
         last_job.status IS NULL)"
    );
    assert_eq!(matched[0].repository_id, repo);
    assert_eq!(matched[0].format, "pypi");
}

// ---------------------------------------------------------------------
// (b2) Quarantined artifact, never scanned (no jobs row), under a
//      SCAN-WAIVED (`scan_backends: []`) policy → NOT returned. The
//      operator explicitly opted out of scanning for this repo; the
//      artifact is not "stranded" — it releases via the existing
//      ScanWaived release authority (ADR 0007) — and enqueueing a scan
//      job for it would contradict that policy. This is the
//      resolved-policy-scans guard #115 item2 adds.
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_skips_quarantined_artifact_with_no_scan_job_under_scan_waived_policy() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_scan_waived_policy(&pool, repo).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined"), None).await;
    // No scan job seeded at all.

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "a job-less quarantined artifact under a scan_backends:[] policy \
         is NOT stranded — it releases via the ScanWaived authority, and \
         must not receive an operator-contradicting scan enqueue"
    );
}

// ---------------------------------------------------------------------
// (c) Quarantined artifact, last scan job pending (in flight) → NOT returned
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_skips_quarantined_artifact_with_pending_last_scan() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined"), None).await;
    let _job = seed_scan_job(&pool, repo, artifact, "pending").await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "a scan already in flight must NOT be re-picked — last_job.status \
         != 'failed' excludes it"
    );
}

// ---------------------------------------------------------------------
// (d) Released artifact with a failed scan job → NOT returned
//     (that predicate belongs to select_eligible, not select_stranded)
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_skips_released_artifact_even_with_failed_scan() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("released"), None).await;
    let _job = seed_scan_job(&pool, repo, artifact, "failed").await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "a released artifact is not stranded regardless of scan-job \
         history — select_stranded only ever picks quarantine_status='quarantined'"
    );
}

// ---------------------------------------------------------------------
// (e) scan_indeterminate artifact with a failed scan job → RETURNED.
//     The ADR 0007 "A reached verdict supersedes an absent one" half:
//     the state is a hold, so a rescan has somewhere to land — a
//     non-blocking verdict returns the artifact to `quarantined` and a
//     blocking one condemns it. This assertion was the exact inverse
//     until that amendment, and the exclusion was what made the state
//     terminal in practice: this query is the only thing that re-picks
//     an artifact for a scan, so nothing else could have delivered the
//     verdict the transition table now admits.
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_returns_scan_indeterminate_artifact_with_failed_last_scan() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    let _job = seed_scan_job(&pool, repo, artifact, "failed").await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    let matched = filter_to(&rows, &[artifact]);
    assert_eq!(
        matched.len(),
        1,
        "an artifact held for want of a verdict must be re-picked for a scan — \
         it is the only mechanism that can deliver one"
    );
    assert_eq!(matched[0].repository_id, repo);
    assert_eq!(matched[0].format, "pypi");
}

// ---------------------------------------------------------------------
// (e2) scan_indeterminate with NO scan job at all → RETURNED. The
//      job-absent arm reaches the new status too; a state is either in
//      the predicate or it is not, and the two arms must not disagree
//      about which.
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_returns_scan_indeterminate_artifact_with_no_scan_job_under_scanning_policy(
) {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let artifact = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert_eq!(
        filter_to(&rows, &[artifact]).len(),
        1,
        "the job-absent arm admits scan_indeterminate exactly as the \
         failed-job arm does"
    );
}

// ---------------------------------------------------------------------
// (e2b) scan_indeterminate whose last scan job COMPLETED → NOT
//       returned. This is the sweep half of "a scan that answered must
//       not be recorded as a scan that failed": the no-verdict arm now
//       completes its row, and the predicate's
//       `last_job.status = 'failed' OR IS NULL` is what then declines
//       the artifact.
//
//       The query is unchanged and correct — it was being fed a wrong
//       fact. What this pins is the consequence for THIS tick: the
//       every-tick re-enqueue is gone, because the interval sweep
//       admits `released`/NULL only and the first two disjuncts here
//       require a failed or absent job.
//
//       It is not the end of the question. The absent-verdict disjunct
//       below re-admits exactly this row once the resolved rescan
//       interval has elapsed, which is the right cadence rather than
//       never: the answer can change without a curator — the policy
//       gains a `scan_backends` entry, or a backend learns the format —
//       and nothing emits an event when it does. So the pair reads
//       "not on every tick, but on the interval", and the test below
//       covers the default-interval half of the cooldown while
//       `select_stranded_skips_a_scan_indeterminate_artifact_re_asked_within_the_interval`
//       covers the explicitly-configured half.
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_skips_scan_indeterminate_artifact_with_a_fresh_completed_scan() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let artifact = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    // Exactly the row a `NothingAnalysable` scan leaves behind: the
    // artifact held for want of a verdict, the job completed because
    // every backend ran and reported. Seeded now, so the rescan
    // cooldown below has not elapsed for it.
    let _job = seed_scan_job(&pool, repo, artifact, "completed").await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "a completed scan job is not a stranded one on this tick — the sweep exists to \
         re-drive a scan that could not run, and re-asking one that ran and answered on \
         every tick would repeat the same answer forever. A `scan_indeterminate` row whose \
         scan completed is re-driven only once its rescan interval has elapsed, which is a \
         separate arm of the predicate and is covered by its own test"
    );

    // The counter-assertion, over the same seeded shape: flip only the
    // job's status and the artifact comes back. Without it a predicate
    // that stopped admitting `scan_indeterminate` at all — or a policy
    // row a sibling left behind — would satisfy the assertion above
    // while saying nothing about the job status at all.
    let failed_artifact = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    let _failed_job = seed_scan_job(&pool, repo, failed_artifact, "failed").await;
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");
    assert_eq!(
        filter_to(&rows, &[failed_artifact]).len(),
        1,
        "the job's status is what decides it: the identical artifact with a failed last scan \
         is still selected, so the skip above is about the row and not about the status"
    );
}

// ---------------------------------------------------------------------
// (e3) scan_indeterminate under a `scan_backends: []` policy → NOT
//      returned. The scan-policy guard is status-agnostic: enqueueing a
//      scan for a scope the operator declared unscanned contradicts
//      their own policy whichever hold the artifact sits in.
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_skips_scan_indeterminate_artifact_under_scan_waived_policy() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_scan_waived_policy(&pool, repo).await;
    let artifact = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    let _job = seed_scan_job(&pool, repo, artifact, "failed").await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "a scan_backends: [] scope is an explicit operator opt-out of \
         scanning — widening the status set does not widen past it"
    );
}

// ---------------------------------------------------------------------
// (e4) A soft-deleted scan_indeterminate artifact → NOT returned. The
//      soft-delete exclusion is per-statement, so the status widening
//      has to be asserted against it rather than inferred from the
//      `quarantined` sibling below.
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_skips_soft_deleted_scan_indeterminate_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let artifact = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    let _job = seed_scan_job(&pool, repo, artifact, "failed").await;
    hort_adapters_postgres::test_support::soft_delete_artifact(&pool, artifact).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "deletion already took the artifact out of service — scanning it \
         buys no serving decision, and its stream is terminal"
    );
}

// ---------------------------------------------------------------------
// (f) rejected artifact with a failed scan job → NOT returned
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_skips_rejected_artifact_even_with_failed_scan() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("rejected"), None).await;
    let _job = seed_scan_job(&pool, repo, artifact, "failed").await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "rejected is terminal — select_stranded must NOT re-pick it \
         (sticky-rejection invariant, same as select_eligible)"
    );
}

// ---------------------------------------------------------------------
// (g) Older failed job + newer in-flight job for the same artifact →
//     NOT returned. Proves the LATERAL ordering picks the MOST RECENT
//     job (not "any failed job ever"), so a fresh re-scan already in
//     flight is not double-enqueued.
// ---------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_skips_artifact_with_newer_in_flight_job_despite_older_failed_job() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined"), None).await;
    let now = Utc::now();
    // Older exhausted attempt.
    let _old_failed = seed_scan_job_at(
        &pool,
        repo,
        artifact,
        "failed",
        now - ChronoDuration::hours(2),
    )
    .await;
    // A fresh rescan already enqueued and now in flight (e.g. by a
    // manual rescan) — this is the MOST RECENT job for the artifact.
    let _new_pending = seed_scan_job_at(&pool, repo, artifact, "pending", now).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "the most-recent job (pending) must gate eligibility, not the \
         older failed one — otherwise a fresh in-flight rescan would be \
         double-enqueued"
    );
}

// =====================================================================
// Soft delete — a deleted artifact is in NEITHER sweep, and consumes no
// batch slot in either.
//
// Both queries lost their liveness predicate when the inert `is_deleted`
// column was dropped, one day before real soft delete arrived under the
// name `deleted_at`. `ArtifactDeleted` is terminal on the artifact's
// stream, so a scan verdict appended afterwards would put a lifecycle
// event past the terminal; and because both queries are `LIMIT`-bounded,
// a deleted row does not merely appear — it takes a slot. The slot is
// what the `batch_size = 1` pairs below assert, which absence alone
// cannot show.
// =====================================================================

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_skips_soft_deleted_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    // Eligible on every other count: released, never scanned, no job.
    let artifact = seed_artifact(&pool, repo, Some("released"), None).await;
    hort_adapters_postgres::test_support::soft_delete_artifact(&pool, artifact).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_eligible(1000, Utc::now())
        .await
        .expect("select_eligible Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "a soft-deleted artifact is out of the served catalog, so \
         rescanning it buys no serving decision — and ArtifactDeleted is \
         terminal, so the verdict would land past it"
    );
}

/// The slot, not just the absence: with `batch_size = 1` and one deleted
/// artifact alongside one live one, the sweep must return the live one.
///
/// Deterministic because the predicate makes the deleted row a
/// non-candidate, leaving exactly one row the `LIMIT 1` can choose from —
/// neither query carries an `ORDER BY`, so that is the whole of the
/// guarantee. Before the fix both were candidates and either could fill
/// the batch, which is how a backlog of deleted rows starves rescanning.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_eligible_spends_no_batch_slot_on_a_soft_deleted_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let deleted = seed_artifact(&pool, repo, Some("released"), None).await;
    hort_adapters_postgres::test_support::soft_delete_artifact(&pool, deleted).await;
    let live = seed_artifact(&pool, repo, Some("released"), None).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_eligible(1, Utc::now())
        .await
        .expect("select_eligible Ok");

    assert_eq!(
        filter_to(&rows, &[deleted, live])
            .iter()
            .map(|c| c.artifact_id)
            .collect::<Vec<_>>(),
        vec![live],
        "the one batch slot must go to the live artifact"
    );
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_skips_soft_deleted_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    // Stranded on every other count: quarantined with no scan job at all.
    let artifact = seed_artifact(&pool, repo, Some("quarantined"), None).await;
    hort_adapters_postgres::test_support::soft_delete_artifact(&pool, artifact).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "a soft-deleted quarantined artifact is not stranded work — \
         deletion already took it out of service"
    );
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_spends_no_batch_slot_on_a_soft_deleted_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let deleted = seed_artifact(&pool, repo, Some("quarantined"), None).await;
    hort_adapters_postgres::test_support::soft_delete_artifact(&pool, deleted).await;
    let live = seed_artifact(&pool, repo, Some("quarantined"), None).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert_eq!(
        filter_to(&rows, &[deleted, live])
            .iter()
            .map(|c| c.artifact_id)
            .collect::<Vec<_>>(),
        vec![live],
        "the one batch slot must go to the live artifact"
    );
}

/// The filter excludes deleted rows and nothing else. Both sweeps keep
/// returning a live artifact that is otherwise identical to the deleted
/// one above — the direction a too-broad predicate (`deleted_at IS NOT
/// NULL`, a stray `AND`) would break silently.
#[tokio::test]
#[serial(hort_pg_db)]
async fn both_sweeps_still_return_a_live_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let eligible = seed_artifact(&pool, repo, Some("released"), None).await;
    let stranded = seed_artifact(&pool, repo, Some("quarantined"), None).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let eligible_rows = port
        .select_eligible(1000, Utc::now())
        .await
        .expect("select_eligible Ok");
    let stranded_rows = port
        .select_stranded(1000, Utc::now())
        .await
        .expect("select_stranded Ok");

    assert_eq!(
        filter_to(&eligible_rows, &[eligible]).len(),
        1,
        "the liveness predicate must not exclude a live artifact"
    );
    assert_eq!(
        filter_to(&stranded_rows, &[stranded]).len(),
        1,
        "the liveness predicate must not exclude a live artifact"
    );
}

// =====================================================================
// The absent-verdict arm of `select_stranded` — the existing-estate
// cutover's first two populations.
//
// A `scan_indeterminate` artifact is held for want of a verdict and
// nothing but this query re-picks it. The two arms above read the most
// recent scan job's *status*, which cannot see the artifact a job that
// ran cleanly and reported nothing to analyse left behind: that job is
// `completed`. These tests pin the third arm, which asks the artifact's
// own status and bounds the re-ask by the resolved rescan interval
// against the job's `created_at`.
// =====================================================================

/// Population (b): the artifact a *completed* no-verdict scan left held.
/// Neither status arm admits it, and this is the whole coupling the
/// cutover closes — the interval has elapsed, so the question is re-asked.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_returns_a_scan_indeterminate_artifact_whose_no_verdict_job_completed() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let now = Utc::now();
    let artifact = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    // A scan in which every backend ran and reported nothing to analyse:
    // the row is `completed`, because nothing failed.
    let _job = seed_scan_job_at(
        &pool,
        repo,
        artifact,
        "completed",
        now - ChronoDuration::hours(30),
    )
    .await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, now)
        .await
        .expect("select_stranded Ok");

    assert_eq!(
        filter_to(&rows, &[artifact]).len(),
        1,
        "a hold whose last scan job COMPLETED without reaching a verdict has no other \
         selection signal at all: `select_eligible`'s statuses exclude it and the two \
         job-status arms do not match it"
    );
}

/// The same row, re-asked within the interval, is not re-asked again.
/// Without this the cutover would re-enqueue a scan for every
/// deterministically-unanalysable artifact on every five-minute tick —
/// the hot loop the job-status arms were accidentally preventing.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_skips_a_scan_indeterminate_artifact_re_asked_within_the_interval() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let now = Utc::now();
    let artifact = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    let _job = seed_scan_job_at(
        &pool,
        repo,
        artifact,
        "completed",
        now - ChronoDuration::hours(1),
    )
    .await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, now)
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "an absent-verdict question re-asked an hour ago under a 24h interval must not be \
         re-asked again on this tick"
    );
}

/// The arm reads the *resolved* interval, not a constant: a 168h policy
/// holds the same row back at 30h and admits it at 200h.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_absent_verdict_arm_honours_the_resolved_interval() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 168).await;
    let now = Utc::now();
    let recent = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    let _recent_job = seed_scan_job_at(
        &pool,
        repo,
        recent,
        "completed",
        now - ChronoDuration::hours(30),
    )
    .await;
    let stale = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    let _stale_job = seed_scan_job_at(
        &pool,
        repo,
        stale,
        "completed",
        now - ChronoDuration::hours(200),
    )
    .await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, now)
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[recent]).is_empty(),
        "30h is inside a 168h interval — the row the policy still considers freshly asked \
         must not be re-asked"
    );
    assert_eq!(
        filter_to(&rows, &[stale]).len(),
        1,
        "200h is past a 168h interval, so the same shape is re-asked — which is what \
         proves the bound is the policy's number and not a constant beside it"
    );
}

/// `rescan_interval_hours = 0` turns off the interval rescan of a live,
/// already-assessed artifact. It is not an instruction to hold an
/// unassessed artifact forever, and reading it as one would make this
/// query — the only one that reaches the hold — unreachable for exactly
/// the operators who disabled cadence rescanning.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_absent_verdict_arm_reads_a_zero_interval_as_the_default() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 0).await;
    let now = Utc::now();
    let artifact = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    let _job = seed_scan_job_at(
        &pool,
        repo,
        artifact,
        "completed",
        now - ChronoDuration::hours(30),
    )
    .await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, now)
        .await
        .expect("select_stranded Ok");

    assert_eq!(
        filter_to(&rows, &[artifact]).len(),
        1,
        "a zero interval must fall back to the DefaultPolicy cooldown, not to never"
    );

    // And the fallback is a cooldown rather than "always": the same
    // policy with a job requested an hour ago still holds the row back,
    // so `make_interval(hours => 0)` is not what the predicate computes.
    let fresh = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    let _fresh_job = seed_scan_job_at(
        &pool,
        repo,
        fresh,
        "completed",
        now - ChronoDuration::hours(1),
    )
    .await;
    let rows = port
        .select_stranded(1000, now)
        .await
        .expect("select_stranded Ok");
    assert!(
        filter_to(&rows, &[fresh]).is_empty(),
        "a zero interval must not collapse the cooldown to zero"
    );
}

/// Population (a) as it stands in a deployed estate, and the direction
/// the cooldown must NOT change: a hold whose last scan attempt errored
/// is re-picked immediately, with no interval wait, because a scanner
/// outage is transient and the sweep's job is to catch its recovery.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_still_returns_a_failed_scan_hold_with_no_cooldown() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let now = Utc::now();
    let held = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    let _held_job = seed_scan_job_at(
        &pool,
        repo,
        held,
        "failed",
        now - ChronoDuration::minutes(1),
    )
    .await;
    let quarantined = seed_artifact(&pool, repo, Some("quarantined"), None).await;
    let _quarantined_job = seed_scan_job_at(
        &pool,
        repo,
        quarantined,
        "failed",
        now - ChronoDuration::minutes(1),
    )
    .await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, now)
        .await
        .expect("select_stranded Ok");

    assert_eq!(
        filter_to(&rows, &[held]).len(),
        1,
        "an errored scan is eligible immediately — the cooldown governs only the rows the \
         status arms cannot see"
    );
    assert_eq!(
        filter_to(&rows, &[quarantined]).len(),
        1,
        "and the same for the other hold, unchanged"
    );
}

/// The counter-direction, and the reason the cooldown arm is scoped to
/// one status: a `quarantined` artifact whose scan COMPLETED has its
/// verdict and is simply mid-window. However old that job is, it is not
/// stranded, and admitting it would re-scan the healthy estate.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_skips_a_quarantined_artifact_with_a_completed_job_however_old() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let now = Utc::now();
    let artifact = seed_artifact(&pool, repo, Some("quarantined"), None).await;
    let _job = seed_scan_job_at(
        &pool,
        repo,
        artifact,
        "completed",
        now - ChronoDuration::hours(5_000),
    )
    .await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, now)
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "a quarantined artifact with a completed scan is mid-window, not stranded — the \
         absent-verdict cooldown must not reach it"
    );
}

/// A `scan_indeterminate` artifact under an explicit `scan_backends: []`
/// waiver stays out of the new arm too, exactly as it stays out of the
/// two status arms: enqueueing a scan would contradict the operator's
/// own policy.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_stranded_absent_verdict_arm_still_honours_a_scan_waiver() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_scan_waived_policy(&pool, repo).await;
    let now = Utc::now();
    let artifact = seed_artifact(&pool, repo, Some("scan_indeterminate"), None).await;
    let _job = seed_scan_job_at(
        &pool,
        repo,
        artifact,
        "completed",
        now - ChronoDuration::hours(30),
    )
    .await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_stranded(1000, now)
        .await
        .expect("select_stranded Ok");

    assert!(
        filter_to(&rows, &[artifact]).is_empty(),
        "a scan waiver is an operator decision the cutover does not override"
    );
}

// =====================================================================
// `select_composite_unassessed` — the cutover's third population:
// a live OCI image manifest with no composite assessment on record.
//
// Not held, so `select_stranded`'s statuses exclude it; its own
// `last_scan_at` may be minutes old, so `select_eligible`'s interval
// excludes it too — while the evidence it serves on was reached under a
// rule in which the composed image's verdict carried no release
// authority.
// =====================================================================

/// Seed an artifact row at an arbitrary `path`, so a test can write the
/// manifest-shaped path (`manifests/sha256:<hex>`) the OCI coords
/// convention uses and which is the only thing in the schema that says
/// "this row is a manifest" — `ArtifactKind` is not persisted.
async fn seed_artifact_at_path(
    pool: &PgPool,
    repo: Uuid,
    quarantine_status: Option<&str>,
    path: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let key = id.simple().to_string();
    let sha256 = format!("{key}{key}");
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key,
               quarantine_status
           ) VALUES (
               $1, $2, 'rescan-it', 'rescan-it', '0.0.0', $3,
               0, $4, 'application/octet-stream', $4,
               $5
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(path)
    .bind(&sha256)
    .bind(quarantine_status)
    .execute(pool)
    .await
    .expect("seed artifact row at an explicit path");
    id
}

/// Seed a manifest-shaped artifact row — the digest in the path is the
/// row's own checksum, as the write path produces.
async fn seed_manifest(pool: &PgPool, repo: Uuid, quarantine_status: Option<&str>) -> Uuid {
    let digest = Uuid::new_v4().simple().to_string();
    seed_artifact_at_path(
        pool,
        repo,
        quarantine_status,
        &format!("manifests/sha256:{digest}{digest}"),
    )
    .await
}

/// Record the stored OCI media type the way the write path does, so a
/// test can make a manifest row an image index.
async fn seed_oci_media_type(pool: &PgPool, artifact: Uuid, media_type: &str) {
    sqlx::query(
        "INSERT INTO public.artifact_metadata (artifact_id, format, metadata) \
         VALUES ($1, 'oci', jsonb_build_object('oci_media_type', $2::text))",
    )
    .bind(artifact)
    .bind(media_type)
    .execute(pool)
    .await
    .expect("seed artifact_metadata oci_media_type");
}

/// Record a composite assessment for a manifest — the row whose
/// *existence* is what takes the manifest out of this predicate.
async fn seed_composite_observation(pool: &PgPool, repo: Uuid, artifact: Uuid, assessment: &str) {
    let digest: String =
        sqlx::query_scalar("SELECT checksum_sha256 FROM public.artifacts WHERE id = $1")
            .bind(artifact)
            .fetch_one(pool)
            .await
            .expect("read back the manifest digest");
    sqlx::query(
        r#"INSERT INTO public.composite_scan_observations (
               artifact_id, repository_id, manifest_digest, scanner, observed_at,
               assessment, reason, already_present, fetched, fetched_bytes,
               severity_critical, severity_high, severity_medium, severity_low,
               severity_negligible, finding_count, distinct_vulnerability_count,
               primary_findings_decision
           ) VALUES (
               $1, $2, $3, 'trivy', now(),
               $4, NULL, 0, 0, 0,
               0, 0, 0, 0,
               0, 0, 0,
               'clean'
           )"#,
    )
    .bind(artifact)
    .bind(repo)
    .bind(digest)
    .bind(assessment)
    .execute(pool)
    .await
    .expect("seed composite_scan_observations row");
}

/// Population (c): a released manifest hort has never composite-assessed.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_returns_a_released_manifest_with_no_observation() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_policy(&pool, repo, 24).await;
    let manifest = seed_manifest(&pool, repo, Some("released")).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_composite_unassessed(1000)
        .await
        .expect("select_composite_unassessed Ok");

    let matched = filter_to(&rows, &[manifest]);
    assert_eq!(
        matched.len(),
        1,
        "a released manifest with no composite assessment on record is serving on \
         evidence the composed-verdict rule did not produce, and no other sweep \
         reaches it promptly"
    );
    assert_eq!(matched[0].repository_id, repo);
    assert_eq!(matched[0].format, "pypi");
    assert_eq!(
        matched[0].rescan_interval_hours, 0,
        "this query has no interval concept, so the candidate carries the sentinel"
    );
}

/// The permissive-default live state is in scope for the same reason it
/// is in `select_eligible`: a `NULL`-status artifact is downloadable.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_returns_a_null_status_manifest() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let manifest = seed_manifest(&pool, repo, None).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_composite_unassessed(1000)
        .await
        .expect("select_composite_unassessed Ok");

    assert_eq!(
        filter_to(&rows, &[manifest]).len(),
        1,
        "a permissive-default manifest is live and downloadable, so it is in scope"
    );
}

/// A manifest with no `artifact_metadata` row at all — the
/// pre-metadata-migration shape — is in scope, mirroring
/// `resolve_media_type`'s own fallback to the single-image default. This
/// is the population most likely to predate composite scanning entirely,
/// so excluding it would miss the oldest rows.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_returns_a_manifest_with_no_stored_media_type() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let manifest = seed_manifest(&pool, repo, Some("released")).await;
    let metadata_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.artifact_metadata WHERE artifact_id = $1")
            .bind(manifest)
            .fetch_one(&pool)
            .await
            .expect("count metadata rows");
    assert_eq!(metadata_rows, 0, "the fixture's premise: no metadata row");

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_composite_unassessed(1000)
        .await
        .expect("select_composite_unassessed Ok");

    assert_eq!(
        filter_to(&rows, &[manifest]).len(),
        1,
        "an absent stored media type must read as the single-image default, not as an \
         exclusion"
    );
}

/// The self-limiting half, and the reason the predicate is the *absence*
/// of an observation rather than the absence of a successful one: every
/// composite scan records a row, whatever it concluded, so a reassessed
/// manifest leaves the set on the next tick — including when the
/// reassessment refused.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_skips_a_manifest_with_any_recorded_observation() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let port = PgRescanCandidatesRepository::new(pool.clone());

    for assessment in [
        "assessed",
        "nothing_to_compose",
        "deterministic_refusal",
        "transient_refusal",
    ] {
        let repo = seed_repo(&pool).await;
        let manifest = seed_manifest(&pool, repo, Some("released")).await;
        // The premise: without the observation it IS a candidate.
        let before = port
            .select_composite_unassessed(1000)
            .await
            .expect("select_composite_unassessed Ok");
        assert_eq!(
            filter_to(&before, &[manifest]).len(),
            1,
            "{assessment}: the fixture must be a candidate before the observation lands"
        );

        seed_composite_observation(&pool, repo, manifest, assessment).await;

        let after = port
            .select_composite_unassessed(1000)
            .await
            .expect("select_composite_unassessed Ok");
        assert!(
            filter_to(&after, &[manifest]).is_empty(),
            "{assessment}: a recorded assessment takes the manifest out of the set, which \
             is what makes one invocation per population terminate"
        );
    }
}

/// An image index composes nothing of its own — its children are the
/// manifests that do — so a composite assessment is not something it
/// can lack.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_skips_an_image_index() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let port = PgRescanCandidatesRepository::new(pool.clone());

    for media_type in [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ] {
        let repo = seed_repo(&pool).await;
        let index = seed_manifest(&pool, repo, Some("released")).await;
        seed_oci_media_type(&pool, index, media_type).await;

        let rows = port
            .select_composite_unassessed(1000)
            .await
            .expect("select_composite_unassessed Ok");
        assert!(
            filter_to(&rows, &[index]).is_empty(),
            "{media_type} is an index, which composes nothing of its own"
        );
    }

    // The counter-direction, so the media-type exclusion is not simply
    // excluding every manifest: a single-image media type is in scope.
    let repo = seed_repo(&pool).await;
    let image = seed_manifest(&pool, repo, Some("released")).await;
    seed_oci_media_type(&pool, image, "application/vnd.oci.image.manifest.v1+json").await;
    let rows = port
        .select_composite_unassessed(1000)
        .await
        .expect("select_composite_unassessed Ok");
    assert_eq!(
        filter_to(&rows, &[image]).len(),
        1,
        "a single-image manifest is exactly what this predicate is for"
    );
}

/// Only manifest-shaped rows. A released npm tarball has no composition
/// of its own and the composite rule says nothing about it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_skips_a_non_manifest_artifact() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let tarball = seed_artifact(&pool, repo, Some("released"), None).await;
    // A blob row under the OCI coords convention is not a manifest row
    // either — the path prefix is what discriminates.
    let blob = seed_artifact_at_path(
        &pool,
        repo,
        Some("released"),
        "blobs/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_composite_unassessed(1000)
        .await
        .expect("select_composite_unassessed Ok");

    assert!(
        filter_to(&rows, &[tarball, blob]).is_empty(),
        "only a manifest row can lack a composite assessment"
    );
}

/// Live only. A held or rejected manifest is not serving, so it is not
/// the population this query exists for — and the two holds are
/// `select_stranded`'s, which must stay the one place that decides when
/// a hold is re-asked.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_skips_a_manifest_that_is_not_live() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let quarantined = seed_manifest(&pool, repo, Some("quarantined")).await;
    let rejected = seed_manifest(&pool, repo, Some("rejected")).await;
    let indeterminate = seed_manifest(&pool, repo, Some("scan_indeterminate")).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_composite_unassessed(1000)
        .await
        .expect("select_composite_unassessed Ok");

    assert!(
        filter_to(&rows, &[quarantined, rejected, indeterminate]).is_empty(),
        "a manifest that is not serving is not this query's population"
    );
}

/// An explicit `scan_backends: []` waiver is an operator decision the
/// cutover does not override, on this query exactly as on
/// `select_stranded`.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_skips_a_manifest_under_a_scan_waived_policy() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let _policy = seed_repo_scoped_scan_waived_policy(&pool, repo).await;
    let manifest = seed_manifest(&pool, repo, Some("released")).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_composite_unassessed(1000)
        .await
        .expect("select_composite_unassessed Ok");

    assert!(
        filter_to(&rows, &[manifest]).is_empty(),
        "enqueueing a scan here would contradict the operator's own policy"
    );
}

/// An in-flight scan already answers the question; a second row would
/// conflict on `jobs_scan_unique` anyway.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_skips_a_manifest_with_an_in_flight_scan() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let manifest = seed_manifest(&pool, repo, Some("released")).await;
    let _job = seed_scan_job(&pool, repo, manifest, "pending").await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_composite_unassessed(1000)
        .await
        .expect("select_composite_unassessed Ok");

    assert!(
        filter_to(&rows, &[manifest]).is_empty(),
        "a pending scan is already the answer arriving"
    );
}

/// Soft delete, the predicate every candidate query shares: a deleted
/// manifest is out of the served catalog, and because the query is
/// `LIMIT`-bounded it would otherwise spend a batch slot a real
/// candidate then does not get.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_spends_no_batch_slot_on_a_soft_deleted_manifest() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let deleted = seed_manifest(&pool, repo, Some("released")).await;
    let live = seed_manifest(&pool, repo, Some("released")).await;
    sqlx::query("UPDATE public.artifacts SET deleted_at = now() WHERE id = $1")
        .bind(deleted)
        .execute(&pool)
        .await
        .expect("soft-delete the manifest");

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_composite_unassessed(1)
        .await
        .expect("select_composite_unassessed Ok");

    assert!(
        filter_to(&rows, &[deleted]).is_empty(),
        "a soft-deleted manifest is out of the served catalog"
    );
    assert_eq!(
        filter_to(&rows, &[live]).len(),
        1,
        "the one batch slot must go to the live manifest"
    );
}

/// A schema this query cannot read is an **error**, not an empty set.
///
/// The predicate is an absence (`NOT EXISTS` over the observation
/// projection), so a read that fails and is reported as "nothing to
/// reassess" is indistinguishable from a finished cutover — the same
/// hazard class `db_gate_not_silent` pins one layer down for a swallowed
/// connect. The handler maps an `Err` to a retryable
/// `TaskOutcome::Failed` and enqueues nothing, which is the fail-closed
/// answer; an `Ok(vec![])` would drain the operator's gauge to zero with
/// the estate untouched.
///
/// The `DROP TABLE` is safe only because `isolated_db_from` hands this
/// test its own database: nothing else will ever connect to it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_errs_when_the_observation_projection_is_unreadable() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let manifest = seed_manifest(&pool, repo, Some("released")).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    // The premise: with the projection in place the manifest IS a
    // candidate, so the assertion below is about the read failing and
    // not about an empty fixture.
    assert_eq!(
        filter_to(
            &port
                .select_composite_unassessed(1000)
                .await
                .expect("select_composite_unassessed Ok"),
            &[manifest]
        )
        .len(),
        1
    );

    sqlx::query("DROP TABLE public.composite_scan_observations")
        .execute(&pool)
        .await
        .expect("drop the observation projection in this test's own database");

    let err = port
        .select_composite_unassessed(1000)
        .await
        .expect_err("an unreadable observation projection must surface as an Err");
    let text = format!("{err}");
    assert!(
        text.contains("composite_scan_observations"),
        "the error should name the relation it could not read: {text}"
    );
}

/// The batch bound is the query's own, so one invocation cannot create an
/// unbounded burst of scan jobs and the next invocation resumes on what
/// is left.
#[tokio::test]
#[serial(hort_pg_db)]
async fn select_composite_unassessed_is_bounded_by_the_batch_size() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let a = seed_manifest(&pool, repo, Some("released")).await;
    let b = seed_manifest(&pool, repo, Some("released")).await;
    let c = seed_manifest(&pool, repo, Some("released")).await;

    let port = PgRescanCandidatesRepository::new(pool.clone());
    let rows = port
        .select_composite_unassessed(2)
        .await
        .expect("select_composite_unassessed Ok");

    assert_eq!(rows.len(), 2, "the LIMIT is the bound on one invocation");
    assert_eq!(
        filter_to(&rows, &[a, b, c]).len(),
        2,
        "and the rows it returned are this fixture's"
    );
}
