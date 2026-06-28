//! `policy-reevaluation` job-kind CHECK — real-adapter enqueue proof
//! (ADR 0041 Item 3).
//!
//! DB-gated proof that the `policy-reevaluation` task kind survives the
//! `jobs.kind` SQL CHECK when enqueued through the **real adapter path**
//! (`JobsRepository::enqueue_task`), complementing the raw-SQL coverage in
//! `migration_009_jobs_and_findings.rs`. This is the "easy miss" surface:
//! a kind added to `VALID_TASK_KINDS` and the worker dispatch but NOT to
//! the `jobs.kind` CHECK (defined inline in `009_scan_jobs_and_findings.sql`)
//! enqueues fine in every mock-based unit test and fails only here —
//! against a real Postgres.
//!
//! ## Isolation contract
//!
//! Every test acquires a real connection via [`maybe_pool`] and therefore
//! carries `#[serial(hort_pg_db)]` per CLAUDE.md → Test Coverage Tiers →
//! DB-backed test isolation: the `hort-adapters-postgres` suite runs in
//! parallel against one shared DB with no per-test isolation, and an
//! enqueue here is a global-scope write.
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

async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    hort_adapters_postgres::test_support::isolated_db_from(&url).await
}

/// The `policy-reevaluation` kind enqueues through the **real adapter
/// path** the production trigger uses (`JobsRepository::enqueue_task`) and
/// lands — proving the `jobs.kind` CHECK admits it. The persisted row
/// round-trips the kind and carries the `'manual'` trigger_source the
/// enqueue path binds.
#[tokio::test]
#[serial(hort_pg_db)]
async fn policy_reevaluation_kind_survives_jobs_kind_check() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    let jobs = PgJobsRepository::new(pool.clone());
    let params = serde_json::json!({
        "policy_id": uuid::Uuid::new_v4(),
        "trigger": { "PolicyUpdated": { "policy_id": uuid::Uuid::new_v4() } },
    });

    let outcome = jobs
        .enqueue_task("policy-reevaluation", &params, None, 0i16, "manual", None)
        .await
        .expect(
            "enqueue_task('policy-reevaluation') must succeed — if this fails with a 23514 \
             check_violation, the jobs.kind CHECK in 009 is missing the kind",
        );
    let job_id = match outcome {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected Enqueued for the None-key path, got {other:?}"),
    };

    let row = sqlx::query("SELECT kind, trigger_source FROM public.jobs WHERE id = $1")
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("re-read enqueued policy-reevaluation row");
    let kind: String = row.get("kind");
    let trigger_source: String = row.get("trigger_source");
    assert_eq!(kind, "policy-reevaluation", "kind round-trip");
    assert_eq!(
        trigger_source, "manual",
        "the re-evaluation enqueue path binds trigger_source='manual'",
    );
}

/// Control: a kind NOT in the CHECK is still rejected with SQLSTATE 23514
/// — proving the `jobs.kind` CHECK is present and constrains the column
/// (a missing constraint would let every kind through).
#[tokio::test]
#[serial(hort_pg_db)]
async fn unknown_kind_still_rejected_by_jobs_kind_check() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    let err = sqlx::query("INSERT INTO public.jobs (kind) VALUES ('not-a-real-kind')")
        .execute(&pool)
        .await
        .expect_err("an unknown kind must be rejected by the jobs.kind CHECK");
    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        code, "23514",
        "expected 23514 check_violation for an unknown kind, got {code}: {err}",
    );
}
