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
//! Coverage matrix (mirrors the §3.2 eligibility predicate):
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

#![allow(clippy::expect_used)]

use std::env;
use std::sync::OnceLock;

use chrono::{Duration as ChronoDuration, Utc};
use serde_json::json;
use sqlx::PgPool;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use uuid::Uuid;

use hort_adapters_postgres::rescan_candidates::PgRescanCandidatesRepository;
use hort_domain::ports::rescan_candidates::RescanCandidatesRepository;

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

/// Per-binary serialization gate. Tests share `public.artifacts`,
/// `public.policy_projections`, and `public.jobs` against a single DB
/// — every test seeds rows with fresh UUIDs and filters its assertions
/// to those UUIDs, but a global Global-scoped policy that `WHERE NOT
/// EXISTS Repository` falls back to could be created by sibling
/// binaries running migrations in parallel. The serial lock confines
/// our policy reads to a single test at a time.
fn serial_lock() -> &'static AsyncMutex<()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(()))
}

async fn lock_serial() -> AsyncMutexGuard<'static, ()> {
    serial_lock().lock().await
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
async fn select_eligible_returns_never_scanned_released_artifact() {
    let _serial = lock_serial().await;
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
async fn select_eligible_skips_recently_scanned_within_interval() {
    let _serial = lock_serial().await;
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
async fn select_eligible_returns_artifact_scanned_before_interval() {
    let _serial = lock_serial().await;
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
async fn select_eligible_skips_zero_interval_disabled_policy() {
    let _serial = lock_serial().await;
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
async fn select_eligible_skips_quarantined_artifact() {
    let _serial = lock_serial().await;
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
async fn select_eligible_skips_rejected_artifact() {
    let _serial = lock_serial().await;
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
async fn select_eligible_skips_artifact_with_pending_scan_job() {
    let _serial = lock_serial().await;
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
async fn select_eligible_returns_artifact_with_completed_scan_job_only() {
    let _serial = lock_serial().await;
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
async fn select_eligible_returns_null_quarantine_artifact() {
    let _serial = lock_serial().await;
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
async fn select_eligible_returns_null_quarantine_no_policy_artifact() {
    let _serial = lock_serial().await;
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
    // here — a Global ScanPolicy created by a sibling test binary would
    // shadow the DefaultPolicy fallback (the residual the `lock_serial`
    // doc names). Test (i) pins the interval deterministically via a
    // repo-scoped policy.
    assert_eq!(
        filter_to(&rows, &[artifact]).len(),
        1,
        "never-scanned NULL-quarantine artifact with no policy must be \
         returned — DefaultPolicy fallback, not dropped by the join"
    );
}
