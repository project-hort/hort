//! A result write belongs to the execution that produced it —
//! `mark_completed` / `reschedule` / `mark_failed` against a real
//! PostgreSQL instance.
//!
//! ## The gap under test
//!
//! A `jobs` row can be executed twice. `requeue_abandoned` returns a
//! row whose holder stopped renewing its lease to `pending`, a sibling
//! claims it, and the original worker — paused rather than dead — may
//! still come back with a result. The three result writes used to be
//! `WHERE id = $1` with no further predicate, so that result landed:
//! `completed` / `failed` / `pending` written over an execution that
//! was still in flight, with `pending` the worst of the three because
//! it invites a third concurrent execution.
//!
//! The fence is the row's `attempts` as the claim returned it. Both
//! claim statements increment the column and nothing else writes it, so
//! it is a per-row execution sequence number — and because the sweep
//! leaves it alone, the two cases a lease holder cannot tell apart
//! become distinguishable:
//!
//! - [`a_superseded_execution_cannot_write_any_of_the_three_results`] —
//!   a sibling claimed the row, so the late result is refused;
//! - [`an_execution_nobody_superseded_still_writes_its_result`] — the
//!   sweep requeued the row but nobody claimed it, so the late result
//!   lands and saves a pointless re-run. Losing this half would be a
//!   regression, not a simplification.
//!
//! `DATABASE_URL`-gated per the project convention: when unset every
//! test early-returns. Every test that acquires a connection carries
//! `#[serial(hort_pg_db)]` — the migration set's `CREATE ROLE` and the
//! stale-database sweeper are cluster-global, so a per-test database is
//! not isolation from a concurrently-running sibling.
//!
//! ```bash
//! DATABASE_URL=postgresql://… \
//!   cargo test -p hort-adapters-postgres --test fenced_result_writes
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::time::Duration;

use serial_test::serial;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_domain::ports::jobs_repository::{
    JobsRepository, RequeueOutcome, ResultWriteOutcome, REQUEUE_ON_LEASE_EXPIRY_KINDS,
};
use hort_domain::types::ContentHash;

/// How long a claim's lease runs in these tests. Long enough that
/// nothing lapses on its own — the tests expire a lease explicitly when
/// they want the sweep to see one.
const LEASE: Duration = Duration::from_secs(900);

/// Fresh per-test database, fully migrated. `None` when `DATABASE_URL`
/// is unset — the single `?`-shaped skip `db_gate_not_silent` permits.
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

fn test_hash() -> ContentHash {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .expect("static valid SHA-256 hex")
}

/// Seed a claimable `kind='scan'` row and return its id.
async fn seed_pending_scan(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO public.jobs \
            (kind, artifact_id, repository_id, content_hash, format, priority, status) \
         VALUES ('scan', $1, $2, $3, 'npm', 0, 'pending') \
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(test_hash().to_string())
    .fetch_one(pool)
    .await
    .expect("seed pending scan row")
}

/// Claim `job_id` for `worker` and return the attempt the claim charged
/// it — the identity that execution writes its result under.
///
/// Goes through the real claim statement rather than an `UPDATE` of its
/// own, because the increment of `attempts` IS the fact under test.
async fn claim_for(repo: &PgJobsRepository, pool: &PgPool, worker: &str, job_id: Uuid) -> u32 {
    let claimed = repo
        .claim_pending_by_kinds(REQUEUE_ON_LEASE_EXPIRY_KINDS, 10, worker, LEASE)
        .await
        .expect("claim_pending_by_kinds");
    let row = claimed
        .iter()
        .find(|j| j.id == job_id)
        .expect("the seeded row is claimable");
    assert_eq!(
        row.attempts,
        current_attempt(pool, job_id).await,
        "the claim must hand back the attempt it wrote",
    );
    row.attempts
}

/// Expire the row's lease far enough into the past that the sweep's
/// grace window has also elapsed. Stands in for the worker that stopped
/// renewing; the alternative is sleeping out a real lease.
async fn expire_lease(pool: &PgPool, job_id: Uuid) {
    sqlx::query("UPDATE public.jobs SET locked_until = now() - interval '1 hour' WHERE id = $1")
        .bind(job_id)
        .execute(pool)
        .await
        .expect("expire the lease");
}

/// Clear the not-before the sweep leaves on a requeued row, so the next
/// claim can take it without waiting out `REQUEUE_BACKOFF`.
async fn clear_not_before(pool: &PgPool, job_id: Uuid) {
    sqlx::query("UPDATE public.jobs SET locked_until = NULL WHERE id = $1")
        .bind(job_id)
        .execute(pool)
        .await
        .expect("clear the not-before");
}

/// Sweep the row's lapsed lease back to `pending`.
async fn sweep(repo: &PgJobsRepository, job_id: Uuid) {
    let resolved = repo
        .requeue_abandoned(
            REQUEUE_ON_LEASE_EXPIRY_KINDS,
            Duration::from_secs(900),
            5,
            100,
        )
        .await
        .expect("requeue_abandoned");
    let row = resolved
        .iter()
        .find(|r| r.id == job_id)
        .expect("the abandoned row is swept");
    assert_eq!(
        row.outcome,
        RequeueOutcome::Requeued,
        "the row is below the attempt cap, so the sweep requeues rather than fails it",
    );
}

async fn current_attempt(pool: &PgPool, job_id: Uuid) -> u32 {
    let attempts: i32 = sqlx::query_scalar("SELECT attempts FROM public.jobs WHERE id = $1")
        .bind(job_id)
        .fetch_one(pool)
        .await
        .expect("read attempts");
    u32::try_from(attempts).expect("attempts is never negative")
}

async fn read_row(pool: &PgPool, job_id: Uuid) -> (String, i32, Option<String>, Option<String>) {
    let row = sqlx::query(
        "SELECT status, attempts, locked_by, last_error FROM public.jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_one(pool)
    .await
    .expect("re-read job row");
    (
        row.try_get("status").expect("status"),
        row.try_get("attempts").expect("attempts"),
        row.try_get("locked_by").expect("locked_by"),
        row.try_get("last_error").expect("last_error"),
    )
}

/// Drive a row through claim → lapsed lease → sweep → re-claim, and
/// return `(job_id, first_attempt, second_attempt)`.
async fn supersede(repo: &PgJobsRepository, pool: &PgPool) -> (Uuid, u32, u32) {
    let job_id = seed_pending_scan(pool).await;
    let first = claim_for(repo, pool, "worker-a", job_id).await;
    expire_lease(pool, job_id).await;
    sweep(repo, job_id).await;
    clear_not_before(pool, job_id).await;
    let second = claim_for(repo, pool, "worker-b", job_id).await;
    assert!(
        second > first,
        "the re-claim must charge a fresh attempt ({first} -> {second})",
    );
    (job_id, first, second)
}

// ---------------------------------------------------------------------------
// The defect — a result from a superseded execution does not land
// ---------------------------------------------------------------------------

/// Worker A's execution was swept and worker B now holds the row. None
/// of A's three result writes may touch it, and each has to say so.
///
/// All three are tried against the same row on purpose: a refusal
/// leaves the row exactly as it found it, so the row's state after the
/// third write is also the assertion that none of the first two moved
/// it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_superseded_execution_cannot_write_any_of_the_three_results() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let (job_id, first, second) = supersede(&repo, &pool).await;
    let refused = ResultWriteOutcome::Superseded {
        current_attempt: second,
    };

    assert_eq!(
        repo.mark_completed(job_id, first, serde_json::json!({"late": true}))
            .await
            .expect("mark_completed"),
        refused,
        "a completion from the superseded execution must not close B's row",
    );
    assert_eq!(
        repo.mark_failed(job_id, first, "A's handler failed")
            .await
            .expect("mark_failed"),
        refused,
        "a failure from the superseded execution must not fail B's row",
    );
    assert_eq!(
        repo.reschedule(
            job_id,
            first,
            Duration::from_secs(60),
            "A's transient failure"
        )
        .await
        .expect("reschedule"),
        refused,
        "a reschedule from the superseded execution is the worst of the three: it would \
         return a row B is running to `pending` and invite a third execution",
    );

    let (status, attempts, locked_by, last_error) = read_row(&pool, job_id).await;
    assert_eq!(status, "running", "the row still belongs to B's execution");
    assert_eq!(locked_by.as_deref(), Some("worker-b"));
    assert_eq!(attempts, i32::try_from(second).expect("small"));
    assert_eq!(
        last_error.as_deref(),
        Some(
            "claim lease expired past the grace window without renewal — the worker holding \
             this row      stopped heartbeating and is presumed dead"
        ),
        "the sweep's diagnosis survives: no refused write rewrote it",
    );
}

/// B's own writes still land while A's are refused — the fence admits
/// the current execution, which is the whole point of fencing rather
/// than locking the row down after a sweep.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_execution_that_holds_the_row_still_closes_it_out() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let (job_id, _first, second) = supersede(&repo, &pool).await;

    assert_eq!(
        repo.mark_completed(job_id, second, serde_json::json!({"ok": true}))
            .await
            .expect("mark_completed"),
        ResultWriteOutcome::Applied,
    );
    let (status, _, _, _) = read_row(&pool, job_id).await;
    assert_eq!(status, "completed");
}

// ---------------------------------------------------------------------------
// The behaviour the sweep's never-delete rule protects
// ---------------------------------------------------------------------------

/// The sweep requeued the row and **nobody claimed it**, so the
/// original execution was never superseded: its late result lands and
/// saves a pointless re-run.
///
/// This is the half a bare `AND locked_by = $2` would have thrown away
/// — the sweep NULLs `locked_by`, so the honest late result and the
/// stale clobber are indistinguishable by that column. One row per
/// write, because each of the three is terminal for the row it lands
/// on.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_execution_nobody_superseded_still_writes_its_result() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    for expected_status in ["completed", "failed", "pending"] {
        let job_id = seed_pending_scan(&pool).await;
        let attempt = claim_for(&repo, &pool, "worker-a", job_id).await;
        expire_lease(&pool, job_id).await;
        sweep(&repo, job_id).await;

        let outcome = match expected_status {
            "completed" => {
                repo.mark_completed(job_id, attempt, serde_json::json!({"late": true}))
                    .await
            }
            "failed" => repo.mark_failed(job_id, attempt, "late failure").await,
            _ => {
                repo.reschedule(job_id, attempt, Duration::from_secs(60), "late transient")
                    .await
            }
        }
        .expect("the late result write");

        assert_eq!(
            outcome,
            ResultWriteOutcome::Applied,
            "a requeued row nobody re-claimed still carries the attempt this execution \
             claimed under, so its {expected_status} result must land",
        );
        let (status, attempts, _, _) = read_row(&pool, job_id).await;
        assert_eq!(status, expected_status);
        assert_eq!(
            attempts,
            i32::try_from(attempt).expect("small"),
            "no result write may move the column it is fenced on",
        );
    }
}

/// At the attempt cap the sweep fails the row instead of requeueing it,
/// and a `failed` row is not claimable — so nothing can move `attempts`
/// past the execution that is still out there, and its late result
/// lands on the terminal row.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_late_result_lands_on_a_row_the_sweep_failed_at_the_cap() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let job_id = seed_pending_scan(&pool).await;
    let attempt = claim_for(&repo, &pool, "worker-a", job_id).await;
    expire_lease(&pool, job_id).await;

    let resolved = repo
        .requeue_abandoned(
            REQUEUE_ON_LEASE_EXPIRY_KINDS,
            Duration::from_secs(900),
            attempt,
            100,
        )
        .await
        .expect("requeue_abandoned");
    assert_eq!(
        resolved
            .iter()
            .find(|r| r.id == job_id)
            .expect("the abandoned row is swept")
            .outcome,
        RequeueOutcome::RetriesExhausted,
    );

    assert_eq!(
        repo.mark_completed(job_id, attempt, serde_json::json!({"late": true}))
            .await
            .expect("mark_completed"),
        ResultWriteOutcome::Applied,
    );
    let (status, _, _, _) = read_row(&pool, job_id).await;
    assert_eq!(status, "completed");
}

// ---------------------------------------------------------------------------
// The third outcome — a row that is not there at all
// ---------------------------------------------------------------------------

/// A deleted row is reported as gone, not as superseded. The two call
/// for different reactions, and reporting a clobber that never happened
/// is its own defect.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_write_to_a_row_that_no_longer_exists_reports_it_gone() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let job_id = seed_pending_scan(&pool).await;
    let attempt = claim_for(&repo, &pool, "worker-a", job_id).await;
    sqlx::query("DELETE FROM public.jobs WHERE id = $1")
        .bind(job_id)
        .execute(&pool)
        .await
        .expect("delete the row out from under the execution");

    for outcome in [
        repo.mark_completed(job_id, attempt, serde_json::Value::Null)
            .await
            .expect("mark_completed"),
        repo.mark_failed(job_id, attempt, "late failure")
            .await
            .expect("mark_failed"),
        repo.reschedule(job_id, attempt, Duration::from_secs(60), "late transient")
            .await
            .expect("reschedule"),
    ] {
        assert_eq!(outcome, ResultWriteOutcome::RowGone);
    }
}
