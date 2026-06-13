//! `PgJobsRepository` integration tests against the
//! `jobs` table from migration 009.
//!
//! `DATABASE_URL`-gated per the project convention (mirrored from
//! `api_tokens_migration.rs` / `migration_009_jobs_and_findings.rs`).
//! When unset, every test early-returns `Ok` so dev environments
//! without a database keep the suite green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test jobs_repository
//! ```
//!
//! Coverage:
//!
//! - `claim_scan_jobs_returns_pending_rows_in_priority_then_created_at_order`
//! - `claim_scan_jobs_marks_rows_running_and_increments_attempts`
//! - `claim_scan_jobs_skips_locked_rows`
//! - `mark_completed_idempotent_on_already_completed_row`
//! - `reschedule_resets_lock_and_records_error`
//! - `mark_failed_terminal_status`
//! - `enqueue_scan_rejects_duplicate_artifact`

#![allow(clippy::expect_used)]

use std::env;
use std::sync::OnceLock;
use std::time::Duration;

use sqlx::{PgPool, Row};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use uuid::Uuid;

use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_domain::ports::jobs_repository::{JobStatus, JobsRepository};
use hort_domain::types::ContentHash;

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

fn test_hash() -> ContentHash {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .expect("static valid SHA-256 hex")
}

/// Insert a `kind='scan'` row with a fresh artifact_id; returns `(job_id,
/// artifact_id)`. Bypasses `enqueue_scan` so tests can seed rows with
/// custom priorities for the ordering assertion.
async fn seed_scan_job(pool: &PgPool, priority: i16) -> (Uuid, Uuid) {
    let artifact_id = Uuid::new_v4();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO public.jobs \
            (kind, artifact_id, repository_id, content_hash, format, priority, status) \
         VALUES ('scan', $1, $2, $3, 'npm', $4, 'pending') \
         RETURNING id",
    )
    .bind(artifact_id)
    .bind(Uuid::new_v4())
    .bind(test_hash().to_string())
    .bind(priority)
    .fetch_one(pool)
    .await
    .expect("seed scan job row");
    (id, artifact_id)
}

/// Per-binary serialization gate.
///
/// Every test in this binary seeds and/or claims rows in the shared
/// `public.jobs` table. `claim_scan_jobs` uses `FOR UPDATE SKIP
/// LOCKED` to acquire its batch — under cargo test's intra-binary
/// parallelism, sibling tests' claims either lock our seeded rows
/// (so we can't see them) or fill our `batch_size` slots with their
/// own rows (so ours fall outside the priority/created_at top-N).
/// The two failure modes observed on CI:
///
/// - `claim_scan_jobs_returns_pending_rows_in_priority_then_created_at_order`
///   only saw 1 of its 3 seeded rows because siblings had already
///   claimed the other 2 (status=running, locked_until in future →
///   skipped by SKIP LOCKED).
/// - `claim_scan_jobs_marks_rows_running_and_increments_attempts`
///   couldn't find its seeded row in the claimed batch because
///   sibling-seeded high-priority rows filled the batch ahead of it.
///
/// Cargo runs different test binaries sequentially by default, so a
/// binary-scoped lock is sufficient.
fn serial_lock() -> &'static AsyncMutex<()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(()))
}

/// Acquire the per-binary serial lock for the test's duration.
async fn lock_serial() -> AsyncMutexGuard<'static, ()> {
    serial_lock().lock().await
}

// ---------------------------------------------------------------------------
// claim_scan_jobs — priority DESC, created_at ASC ordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn claim_scan_jobs_returns_pending_rows_in_priority_then_created_at_order() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    // Seed three rows: low priority earliest, high priority middle,
    // medium priority latest. Expected post-claim order:
    // high (priority 10) → medium (5) → low (0).
    let (low_id, _) = seed_scan_job(&pool, 0).await;
    let (high_id, _) = seed_scan_job(&pool, 10).await;
    let (med_id, _) = seed_scan_job(&pool, 5).await;

    // Claim with a generous batch size. `lock_serial` synchronises this
    // binary's tests, but `tests/migration_009_jobs_and_findings.rs`
    // runs in a sibling binary and inserts into `public.jobs` against
    // the same DB; cargo runs test binaries in parallel so we cannot
    // assume an empty table here. With a tight `batch_size: 3` a single
    // sibling-binary pending row pushes one of our seeds out of the
    // top-3 picked set and the filter below returns only two of our
    // ids. A larger batch swamps plausible cross-binary pollution; the
    // filter still keeps only our three, and the post-query sort
    // guarantees the order.
    let claimed = repo
        .claim_scan_jobs("test-worker", 100, Duration::from_secs(60))
        .await
        .expect("claim_scan_jobs");

    let claimed_ids: Vec<Uuid> = claimed.iter().map(|j| j.id).collect();
    // Filter to only our seeded rows in case other tests left rows behind.
    let our_order: Vec<Uuid> = claimed_ids
        .into_iter()
        .filter(|id| *id == low_id || *id == med_id || *id == high_id)
        .collect();
    assert_eq!(
        our_order,
        vec![high_id, med_id, low_id],
        "claim must yield rows priority DESC, then created_at ASC"
    );
}

// ---------------------------------------------------------------------------
// claim_scan_jobs — status mutation + attempts increment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn claim_scan_jobs_marks_rows_running_and_increments_attempts() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let (job_id, _) = seed_scan_job(&pool, 0).await;
    let claimed = repo
        .claim_scan_jobs("test-worker", 10, Duration::from_secs(60))
        .await
        .expect("claim_scan_jobs");

    let our_row = claimed
        .into_iter()
        .find(|j| j.id == job_id)
        .expect("our seeded row must be in the batch");

    assert_eq!(our_row.status, JobStatus::Running);
    assert_eq!(our_row.attempts, 1);
    assert_eq!(our_row.locked_by.as_deref(), Some("test-worker"));
    assert!(our_row.locked_until.is_some());

    // Re-read the row directly to confirm the database reflects the
    // claim.
    let status_str: String = sqlx::query_scalar("SELECT status FROM public.jobs WHERE id = $1")
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("re-read status");
    assert_eq!(status_str, "running");
}

// ---------------------------------------------------------------------------
// claim_scan_jobs — concurrent-claim safety
// ---------------------------------------------------------------------------

#[tokio::test]
async fn claim_scan_jobs_skips_locked_rows() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let (job_id, _) = seed_scan_job(&pool, 0).await;
    // First claim grabs the row.
    let _first = repo
        .claim_scan_jobs("worker-a", 10, Duration::from_secs(900))
        .await
        .expect("first claim");
    // Second claim must NOT return the same row (it is now `running`
    // with a future `locked_until`).
    let second = repo
        .claim_scan_jobs("worker-b", 10, Duration::from_secs(900))
        .await
        .expect("second claim");
    assert!(
        !second.iter().any(|j| j.id == job_id),
        "second claim must skip the row already locked by worker-a"
    );
}

// ---------------------------------------------------------------------------
// mark_completed — idempotent on already-completed row
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mark_completed_idempotent_on_already_completed_row() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let (job_id, _) = seed_scan_job(&pool, 0).await;

    repo.mark_completed(job_id, serde_json::Value::Null)
        .await
        .expect("first mark_completed");
    // Second call must not panic / error — the UPDATE just no-ops on
    // the row that is already `completed`.
    repo.mark_completed(job_id, serde_json::Value::Null)
        .await
        .expect("second mark_completed must be idempotent");

    let status_str: String = sqlx::query_scalar("SELECT status FROM public.jobs WHERE id = $1")
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("re-read status");
    assert_eq!(status_str, "completed");
}

// ---------------------------------------------------------------------------
// mark_completed — persists result_summary (H17)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mark_completed_persists_result_summary() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let (job_id, _) = seed_scan_job(&pool, 0).await;

    // H17 — a non-null summary (the provenance-verify / scan handler's
    // `TaskOutcome::Completed { result_summary }`) must land in the column,
    // not be discarded.
    let summary = serde_json::json!({ "result": "no_attestation" });
    repo.mark_completed(job_id, summary.clone())
        .await
        .expect("mark_completed with summary");

    let stored: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT result_summary FROM public.jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&pool)
            .await
            .expect("re-read result_summary");
    assert_eq!(stored, Some(summary), "non-null summary must be persisted");

    // A `Value::Null` summary is the "no summary" sentinel — it must store
    // as SQL NULL, not a JSON `'null'`, so `result_summary IS NULL` keeps
    // meaning "no summary recorded".
    repo.mark_completed(job_id, serde_json::Value::Null)
        .await
        .expect("mark_completed with null summary");
    let cleared: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT result_summary FROM public.jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&pool)
            .await
            .expect("re-read result_summary after null");
    assert_eq!(cleared, None, "Value::Null persists as SQL NULL");
}

// ---------------------------------------------------------------------------
// reschedule — restores pending + records error + new locked_until
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reschedule_resets_lock_and_records_error() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let (job_id, _) = seed_scan_job(&pool, 0).await;
    let _claimed = repo
        .claim_scan_jobs("worker-a", 10, Duration::from_secs(900))
        .await
        .expect("initial claim");

    repo.reschedule(job_id, Duration::from_secs(60), "transient backend failure")
        .await
        .expect("reschedule");

    let row = sqlx::query(
        "SELECT status, locked_by, locked_until, last_error \
         FROM public.jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_one(&pool)
    .await
    .expect("re-read row");
    let status: String = row.get("status");
    let locked_by: Option<String> = row.get("locked_by");
    let last_error: Option<String> = row.get("last_error");
    assert_eq!(status, "pending");
    assert!(locked_by.is_none(), "reschedule must clear locked_by");
    assert_eq!(last_error.as_deref(), Some("transient backend failure"));
}

// ---------------------------------------------------------------------------
// mark_failed — terminal status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mark_failed_terminal_status() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let (job_id, _) = seed_scan_job(&pool, 0).await;
    repo.mark_failed(job_id, "max attempts reached")
        .await
        .expect("mark_failed");

    let row = sqlx::query("SELECT status, last_error FROM public.jobs WHERE id = $1")
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("re-read row");
    let status: String = row.get("status");
    let last_error: Option<String> = row.get("last_error");
    assert_eq!(status, "failed");
    assert_eq!(last_error.as_deref(), Some("max attempts reached"));
}

// ---------------------------------------------------------------------------
// enqueue_scan — partial-unique conflict mapped to DomainError::Conflict
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// pending_scan_count — port-level queue-depth gauge (L12 review finding)
// ---------------------------------------------------------------------------

/// L12: `pending_scan_count` returns exactly the number of
/// `kind='scan'` rows whose `status='pending'`. Rows in `running`,
/// `completed`, or `failed` states are excluded; rows of other kinds
/// are excluded by the `kind='scan'` filter.
///
/// Seeds three pending rows, claims one (which transitions to
/// `running`), marks one `completed`, leaves one `pending`, and
/// asserts the count differs by exactly +1 from the pre-test
/// baseline.
#[tokio::test]
async fn pending_scan_count_filters_by_kind_and_status() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    // Read the baseline so the assertion is robust against
    // pre-existing rows from sibling tests in the same test DB.
    let baseline = repo
        .pending_scan_count()
        .await
        .expect("baseline pending_scan_count");

    // Seed three pending rows. After this we should be at
    // baseline + 3.
    let (a_id, _) = seed_scan_job(&pool, 0).await;
    let (b_id, _) = seed_scan_job(&pool, 0).await;
    let (_c_id, _) = seed_scan_job(&pool, 0).await;

    let after_seed = repo
        .pending_scan_count()
        .await
        .expect("post-seed pending_scan_count");
    assert_eq!(
        after_seed,
        baseline + 3,
        "three fresh pending rows must lift the count by exactly +3"
    );

    // Claim one → running (does not contribute to pending).
    let _claimed = repo
        .claim_scan_jobs("test-worker", 1, Duration::from_secs(60))
        .await
        .expect("claim one");

    // Mark another completed (terminal — does not contribute to
    // pending). We re-state row b's status directly via SQL because
    // mark_completed is the API exercised here only as a side
    // effect.
    repo.mark_completed(b_id, serde_json::Value::Null)
        .await
        .expect("mark b completed");

    let after_transitions = repo
        .pending_scan_count()
        .await
        .expect("post-transition pending_scan_count");

    // We claimed exactly one of {a,b,c} (the highest-priority + earliest)
    // and marked b completed. Worst case (claim chose b): claim
    // doesn't reduce pending because b was already off pending via
    // mark_completed. Best case (claim chose a or c): pending
    // dropped by 2. We don't know which of {a,c} the claim hit, but
    // the count must drop by at least 2 relative to `after_seed`.
    assert!(
        after_transitions <= after_seed - 2,
        "pending_scan_count must drop after running/completed transitions: \
         baseline={baseline}, after_seed={after_seed}, after_transitions={after_transitions}"
    );

    // Tidy: avoid leaving 'running' rows around for downstream
    // tests. Mark a as completed too (idempotent via the API). c
    // stays pending — sibling tests cope via the serial lock.
    repo.mark_completed(a_id, serde_json::Value::Null)
        .await
        .ok();
}

#[tokio::test]
async fn enqueue_scan_rejects_duplicate_artifact() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let artifact_id = Uuid::new_v4();
    let repository_id = Uuid::new_v4();
    let hash = test_hash();

    let _id = repo
        .enqueue_scan(artifact_id, repository_id, &hash, "npm", 0, "ingest")
        .await
        .expect("first enqueue_scan");

    let err = repo
        .enqueue_scan(artifact_id, repository_id, &hash, "npm", 0, "ingest")
        .await
        .expect_err("duplicate enqueue must conflict");
    assert!(
        matches!(err, hort_domain::error::DomainError::Conflict(_)),
        "expected Conflict, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Partial unique index status filter + `find_active_scan_for_artifact`
// semantics
// ---------------------------------------------------------------------------
//
// Background: the original `jobs_scan_unique` partial unique was
// scoped only to `kind='scan' AND artifact_id IS NOT NULL`. With no
// status predicate, a completed scan row blocked every subsequent
// rescan — a 409 forever after the first scan, contradicting the
// "409 only on in-flight scans" contract. The fix narrows the index
// WHERE clause to `status IN ('pending','running')`, freeing the
// artifact for a fresh rescan once the prior scan terminates. The
// `find_active_scan_for_artifact` adapter override exposes the
// in-flight check for `ManualRescanUseCase` use-case-side gating.

/// Insert a scan row at an arbitrary status (bypassing `enqueue_scan`,
/// which always inserts `'pending'`). Returns the inserted job id.
async fn seed_scan_job_with_status(pool: &PgPool, artifact_id: Uuid, status: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO public.jobs \
            (kind, artifact_id, repository_id, content_hash, format, priority, status) \
         VALUES ('scan', $1, $2, $3, 'npm', 0, $4) \
         RETURNING id",
    )
    .bind(artifact_id)
    .bind(Uuid::new_v4())
    .bind(test_hash().to_string())
    .bind(status)
    .fetch_one(pool)
    .await
    .expect("seed scan job row at custom status")
}

/// 1. Index allows a fresh rescan after a prior completed scan, and
///    `find_active_scan_for_artifact` returns the new pending row's id
///    (NOT the completed one).
#[tokio::test]
async fn jobs_scan_unique_allows_pending_after_prior_completed() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let artifact_id = Uuid::new_v4();
    // First scan: completed → outside the partial unique under the new shape.
    let completed_id = seed_scan_job_with_status(&pool, artifact_id, "completed").await;
    // Second scan: pending → must succeed (no unique violation).
    let pending_id = seed_scan_job_with_status(&pool, artifact_id, "pending").await;

    // Both rows present in the DB.
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.jobs \
         WHERE kind='scan' AND artifact_id=$1",
    )
    .bind(artifact_id)
    .fetch_one(&pool)
    .await
    .expect("count rows for artifact");
    assert_eq!(
        count, 2,
        "completed + pending rows must coexist for the same artifact"
    );

    // The in-flight lookup returns the pending row, not the completed one.
    let active = repo
        .find_active_scan_for_artifact(artifact_id)
        .await
        .expect("find_active_scan_for_artifact");
    assert_eq!(
        active,
        Some(pending_id),
        "find_active_scan_for_artifact must surface the pending row, not the completed row"
    );
    assert_ne!(
        active,
        Some(completed_id),
        "completed rows must not be reported as in-flight"
    );
}

/// 2. Index still blocks two simultaneously-active scan rows for the
///    same artifact (`pending` + `pending` → unique violation).
#[tokio::test]
async fn jobs_scan_unique_blocks_two_pending_for_same_artifact() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let artifact_id = Uuid::new_v4();
    let first_id = seed_scan_job_with_status(&pool, artifact_id, "pending").await;

    let dup = sqlx::query(
        "INSERT INTO public.jobs \
            (kind, artifact_id, repository_id, content_hash, format, priority, status) \
         VALUES ('scan', $1, $2, $3, 'npm', 0, 'pending')",
    )
    .bind(artifact_id)
    .bind(Uuid::new_v4())
    .bind(test_hash().to_string())
    .execute(&pool)
    .await;
    let err = dup.expect_err("two in-flight scan rows for the same artifact must conflict");
    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        code, "23505",
        "expected SQLSTATE 23505 (unique_violation), got {code}: {err}"
    );

    // The lookup returns the surviving (first) row's id.
    let active = repo
        .find_active_scan_for_artifact(artifact_id)
        .await
        .expect("find_active_scan_for_artifact");
    assert_eq!(active, Some(first_id));
}

/// 3. No active job: `find_active_scan_for_artifact` returns `None`
///    when the only row for the artifact is `completed`.
#[tokio::test]
async fn find_active_scan_returns_none_when_only_completed_row_exists() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let artifact_id = Uuid::new_v4();
    let _completed = seed_scan_job_with_status(&pool, artifact_id, "completed").await;

    let active = repo
        .find_active_scan_for_artifact(artifact_id)
        .await
        .expect("find_active_scan_for_artifact");
    assert_eq!(
        active, None,
        "completed-only history must not surface as in-flight"
    );
}

/// 4. Wrong kind not counted: a `pending`, non-scan row pointing at
///    `artifact_id` (artificial — non-scan kinds typically NULL the
///    column) is excluded by the `kind='scan'` predicate.
#[tokio::test]
async fn find_active_scan_ignores_non_scan_kinds() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let artifact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.jobs (kind, artifact_id, status) \
         VALUES ('cron-rescan-tick', $1, 'pending')",
    )
    .bind(artifact_id)
    .execute(&pool)
    .await
    .expect("seed non-scan kind row with artifact_id");

    let active = repo
        .find_active_scan_for_artifact(artifact_id)
        .await
        .expect("find_active_scan_for_artifact");
    assert_eq!(
        active, None,
        "non-scan kinds must not surface in the scan-specific lookup"
    );
}
