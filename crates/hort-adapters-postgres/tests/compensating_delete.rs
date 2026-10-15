//! DB-backed tests for the compensating delete behind
//! [`JobsRepository::delete_job`] — the rollback `TaskUseCase::enqueue`
//! attempts when the `TaskInvoked` append fails after a successful insert.
//!
//! **What these tests pin.** The statement is `DELETE FROM public.jobs
//! WHERE id = $1 AND status = 'pending'`, and the status half is the
//! load-bearing one. Between the insert and the compensating delete lies a
//! failed event-store append — a network round-trip — and a worker can
//! claim the row inside that window (`pending -> running`) and begin
//! executing the task. A delete without the status predicate removes the
//! claimed row **and the durable single-flight idempotency key it carries**
//! (ADR 0028), so a second authorised invoke inserts afresh under the same
//! key and two executions of a destructive task can run while no
//! `TaskInvoked` exists for the first.
//!
//! [`claimed_row_survives_the_compensating_delete`] is the test that kills
//! the wrong predicate: it claims the row through the real claim statement
//! and asserts the row survives. [`pending_row_is_rolled_back`] is the
//! regression guard for the narrowing — the delete must still do its job on
//! the row it is entitled to remove. [`claimed_rows_idempotency_key_survives`]
//! asserts the consequence that motivates the predicate: the key stays
//! claimed, so a second same-key enqueue still dedups.
//!
//! `DATABASE_URL`-gated: every test self-skips when it is unset, and every
//! test carries `#[serial(hort_pg_db)]` per CLAUDE.md → *DB-backed test
//! isolation* (mandatory; not optional).

#![allow(clippy::expect_used)]

use std::env;
use std::time::Duration;

use serial_test::serial;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_domain::ports::jobs_repository::{CompensatingDelete, EnqueueOutcome, JobsRepository};
use hort_domain::types::IdempotencyKey;

async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

/// Enqueue one `noop` row exactly as the use case does, returning its id.
async fn enqueue_noop(repo: &PgJobsRepository, key: Option<&IdempotencyKey>) -> Uuid {
    match repo
        .enqueue_task("noop", &serde_json::json!({}), None, 0, "manual", key)
        .await
        .expect("enqueue_task")
    {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected a fresh Enqueued row, got {other:?}"),
    }
}

async fn status_of(pool: &PgPool, job_id: Uuid) -> Option<String> {
    sqlx::query("SELECT status FROM public.jobs WHERE id = $1")
        .bind(job_id)
        .fetch_optional(pool)
        .await
        .expect("status read")
        .map(|row| row.get::<String, _>("status"))
}

/// A worker claimed the row inside the append window, so the compensating
/// delete must remove nothing and say so. Without the status predicate this
/// test fails on both halves at once: the row disappears and the outcome
/// reads as a successful rollback.
#[tokio::test]
#[serial(hort_pg_db)]
async fn claimed_row_survives_the_compensating_delete() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let job_id = enqueue_noop(&repo, None).await;

    // The real claim, not a hand-written UPDATE: the transition this delete
    // is scoped against is `CLAIM_PENDING_BY_KINDS_SQL`'s, and a test that
    // wrote `status = 'running'` itself would keep passing if the claim
    // stopped producing that status.
    let claimed = repo
        .claim_pending_by_kinds(
            &["noop"],
            1,
            "worker-compensating-delete",
            Duration::from_secs(60),
        )
        .await
        .expect("claim_pending_by_kinds");
    assert_eq!(claimed.len(), 1, "the enqueued row must be claimable");
    assert_eq!(claimed[0].id, job_id);

    let outcome = repo.delete_job(job_id).await.expect("delete_job");
    assert_eq!(
        outcome,
        CompensatingDelete::NoLongerPending,
        "a claimed row is not the row this delete inserted and may remove; the outcome has \
         to say the statement matched nothing"
    );
    assert_eq!(
        status_of(&pool, job_id).await.as_deref(),
        Some("running"),
        "the claimed row must survive — a worker is executing it, and deleting it strands \
         the execution with no TaskInvoked audit event"
    );
}

/// The narrowing must not break the compensation itself: a row nobody
/// claimed is still deleted, and the outcome says so.
#[tokio::test]
#[serial(hort_pg_db)]
async fn pending_row_is_rolled_back() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let job_id = enqueue_noop(&repo, None).await;
    assert_eq!(
        status_of(&pool, job_id).await.as_deref(),
        Some("pending"),
        "enqueue_task inserts `pending` — the status this delete is scoped to"
    );

    let outcome = repo.delete_job(job_id).await.expect("delete_job");
    assert_eq!(outcome, CompensatingDelete::RolledBack);
    assert!(
        status_of(&pool, job_id).await.is_none(),
        "the unclaimed row must be gone — this is the rollback the caller asked for"
    );
}

/// The consequence that motivates the predicate: because the claimed row
/// survives, so does its durable single-flight idempotency key, and a
/// second authorised invoke under the same key still dedups instead of
/// starting a second execution of a destructive task.
#[tokio::test]
#[serial(hort_pg_db)]
async fn claimed_rows_idempotency_key_survives() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    let key = IdempotencyKey::try_from("cron:retention-purge:2026-10-15").expect("valid key");
    let job_id = enqueue_noop(&repo, Some(&key)).await;
    let claimed = repo
        .claim_pending_by_kinds(
            &["noop"],
            1,
            "worker-compensating-delete",
            Duration::from_secs(60),
        )
        .await
        .expect("claim_pending_by_kinds");
    assert_eq!(claimed.len(), 1);

    let outcome = repo.delete_job(job_id).await.expect("delete_job");
    assert_eq!(outcome, CompensatingDelete::NoLongerPending);

    let second = repo
        .enqueue_task(
            "noop",
            &serde_json::json!({}),
            None,
            0,
            "manual",
            Some(&key),
        )
        .await
        .expect("second enqueue_task");
    assert_eq!(
        second,
        EnqueueOutcome::Duplicate {
            existing_job_id: job_id
        },
        "the claimed row still holds the key, so the second invoke must dedup against it — \
         a delete that removed the row would free the key and admit a second execution"
    );
}
