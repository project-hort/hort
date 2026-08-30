//! `scan-row-retention-sweep` job-kind CHECK — real-adapter enqueue
//! proof for the migration that redefines `jobs_kind_check`.
//!
//! DB-gated proof that the task kind survives the `jobs.kind` SQL CHECK
//! **as a migrated database actually enforces it** — i.e. after
//! `023_jobs_kind_scan_row_retention_sweep.sql` has redefined the
//! constraint on top of `018_jobs_kind_oci_edge_backfill.sql` — when
//! enqueued through the real adapter path
//! (`JobsRepository::enqueue_task`) the admin-task invoke uses. Sibling
//! of `jobs_kind_check_oci_edge_backfill.rs` /
//! `jobs_kind_check_policy_reevaluation.rs`.
//!
//! This is the surface the DB-free
//! `task_kind_check_lockstep_guard.rs` cannot reach: the guard proves the
//! newest defining migration's list agrees with `EVENT_TASK_KINDS`, but
//! only a real migrate-then-INSERT proves that migration applies cleanly
//! to a database that already carries the constraint 018 created, and
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
use sqlx::{PgPool, Row};

use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_domain::ports::jobs_repository::{EnqueueOutcome, JobsRepository};

const KIND: &str = "scan-row-retention-sweep";

async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    hort_adapters_postgres::test_support::isolated_db_from(&url).await
}

/// The sweep kind enqueues through the real adapter path and lands —
/// proving the effective `jobs.kind` CHECK admits it. The persisted row
/// round-trips the kind and carries the `'cron'` trigger_source the
/// scheduled enqueue path binds.
#[tokio::test]
#[serial(hort_pg_db)]
async fn scan_row_retention_sweep_kind_survives_jobs_kind_check() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    let jobs = PgJobsRepository::new(pool.clone());
    let params = serde_json::json!({});

    let outcome = jobs
        .enqueue_task(KIND, &params, None, 10i16, "cron", None)
        .await
        .expect(
            "enqueue_task('scan-row-retention-sweep') must succeed — a 23514 \
             check_violation here means the effective jobs.kind CHECK (the newest migration \
             that redefines it) is missing the kind",
        );
    let job_id = match outcome {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected Enqueued for the None-key path, got {other:?}"),
    };

    let row = sqlx::query("SELECT kind, trigger_source FROM public.jobs WHERE id = $1")
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("re-read enqueued scan-row-retention-sweep row");
    let kind: String = row.get("kind");
    let trigger_source: String = row.get("trigger_source");
    assert_eq!(kind, KIND, "kind round-trip");
    assert_eq!(
        trigger_source, "cron",
        "the scheduled enqueue path binds trigger_source='cron'",
    );
}
