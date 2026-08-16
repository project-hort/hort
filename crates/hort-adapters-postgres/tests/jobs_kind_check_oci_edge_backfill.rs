//! `oci-membership-edge-backfill` job-kind CHECK — real-adapter enqueue
//! proof for the migration that redefines `jobs_kind_check`.
//!
//! DB-gated proof that the task kind survives the `jobs.kind` SQL CHECK
//! **as a migrated database actually enforces it** — i.e. after
//! `018_jobs_kind_oci_edge_backfill.sql` has redefined the constraint on
//! top of `009_scan_jobs_and_findings.sql`'s inline list — when enqueued
//! through the real adapter path (`JobsRepository::enqueue_task`) the
//! admin-task invoke uses. Sibling of
//! `jobs_kind_check_policy_reevaluation.rs`.
//!
//! This is the surface the DB-free
//! `task_kind_check_lockstep_guard.rs` cannot reach: the guard proves the
//! newest defining migration's list agrees with `EVENT_TASK_KINDS`, but
//! only a real migrate-then-INSERT proves that migration applies cleanly
//! to a database that already carries the constraint 009 created, and
//! that the redefined constraint admits the kind.
//!
//! ## Isolation contract
//!
//! Every test acquires a real connection via [`maybe_pool`] and therefore
//! carries `#[serial(hort_pg_db)]` per CLAUDE.md → Test Coverage Tiers →
//! DB-backed test isolation.
//!
//! ## Self-skip without `DATABASE_URL`
//!
//! Like every DB-gated test in this crate, it early-returns silently when
//! `DATABASE_URL` is unset (the local `cargo test --workspace` gate), and
//! runs in CI's Tier-2 integration job which sets the DSN.

#![allow(clippy::expect_used)]

use std::env;

use serial_test::serial;
use sqlx::PgPool;

use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_domain::ports::jobs_repository::{EnqueueOutcome, JobsRepository};

const KIND: &str = "oci-membership-edge-backfill";

async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    hort_adapters_postgres::test_support::isolated_db_from(&url).await
}

/// The backfill kind enqueues through the real adapter path and lands —
/// proving the effective `jobs.kind` CHECK admits it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn oci_membership_edge_backfill_kind_survives_jobs_kind_check() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    let jobs = PgJobsRepository::new(pool.clone());
    let params = serde_json::json!({ "batch_size": 100 });

    let outcome = jobs
        .enqueue_task(KIND, &params, None, 0i16, "manual", None)
        .await
        .expect(
            "enqueue_task('oci-membership-edge-backfill') must succeed — a 23514 \
             check_violation here means the effective jobs.kind CHECK (the newest migration \
             that redefines it) is missing the kind",
        );
    assert!(
        matches!(outcome, EnqueueOutcome::Enqueued { .. }),
        "expected Enqueued for the None-key path, got {outcome:?}",
    );
}

/// The constraint a migrated database carries is the **explicitly named**
/// `jobs_kind_check` the redefining migration adds — not an anonymous
/// re-add under a Postgres-generated name. Future redefinitions drop it
/// by that name, so the name itself is part of the contract.
#[tokio::test]
#[serial(hort_pg_db)]
async fn jobs_kind_check_carries_its_explicit_name() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    let named: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint \
         WHERE conrelid = 'public.jobs'::regclass AND contype = 'c' \
           AND conname = 'jobs_kind_check')",
    )
    .fetch_one(&pool)
    .await
    .expect("probe pg_constraint for jobs_kind_check");
    assert!(
        named,
        "public.jobs must carry a CHECK constraint named `jobs_kind_check` after the migration \
         chain — a future widening drops it by that name",
    );
}
