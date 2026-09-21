//! `oci-index-child-ingest` job-kind CHECK — real-adapter enqueue proof for
//! the migration that redefines `jobs_kind_check`.
//!
//! DB-gated proof that the task kind survives the `jobs.kind` SQL CHECK **as a
//! migrated database actually enforces it** — i.e. after
//! `024_jobs_kind_oci_index_child_ingest.sql` has redefined the constraint on
//! top of `023_jobs_kind_scan_row_retention_sweep.sql` — when enqueued through
//! the real adapter path (`JobsRepository::enqueue_task`) the handler's own
//! grandchild recursion uses. Sibling of
//! `jobs_kind_check_scan_row_retention_sweep.rs` /
//! `jobs_kind_check_oci_edge_backfill.rs` /
//! `jobs_kind_check_policy_reevaluation.rs`.
//!
//! This is the surface the DB-free `task_kind_check_lockstep_guard.rs` cannot
//! reach: the guard proves the newest defining migration's list agrees with
//! `EVENT_TASK_KINDS`, but only a real migrate-then-INSERT proves that
//! migration applies cleanly to a database that already carries the constraint
//! 023 created, and that the redefined constraint admits the kind.
//!
//! It additionally pins the per-row dedupe contract this kind depends on: the
//! composed `(repository_id, child_digest)` idempotency key must survive the
//! `jobs_idempotency_key_charset_chk` CHECK, and a second enqueue under the
//! same key must be absorbed by `jobs_idempotency_key_uq` rather than minting a
//! duplicate upstream fetch.
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
//! `DATABASE_URL` is unset (the local `cargo test --workspace` gate), and runs
//! in CI's Tier-2 integration job which sets the DSN.

#![allow(clippy::expect_used)]

use std::env;

use serial_test::serial;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_domain::ports::jobs_repository::{EnqueueOutcome, JobsRepository};
use hort_domain::types::IdempotencyKey;

const KIND: &str = "oci-index-child-ingest";

async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    hort_adapters_postgres::test_support::isolated_db_from(&url).await
}

/// The composed key shape the handler mints:
/// `oci-index-child-ingest:{repository_id}:sha256:{hex}`.
fn dedupe_key(repository_id: Uuid, hex: &str) -> IdempotencyKey {
    IdempotencyKey::try_from(format!("{KIND}:{repository_id}:sha256:{hex}"))
        .expect("the composed dedupe key must satisfy the domain validator")
}

/// The kind enqueues through the real adapter path and lands — proving the
/// effective `jobs.kind` CHECK admits it. The persisted row round-trips the
/// kind, the `'ingest'` trigger_source the handler binds, and the params shape
/// the consumer deserializes.
#[tokio::test]
#[serial(hort_pg_db)]
async fn oci_index_child_ingest_kind_survives_jobs_kind_check() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    let jobs = PgJobsRepository::new(pool.clone());
    let repository_id = Uuid::new_v4();
    let hex = "a".repeat(64);
    let params = serde_json::json!({
        "repository_id": repository_id,
        "requested_name": "dockerhub/library/nginx",
        "child_digest": format!("sha256:{hex}"),
    });
    let key = dedupe_key(repository_id, &hex);

    let outcome = jobs
        .enqueue_task(KIND, &params, None, 0i16, "ingest", Some(&key))
        .await
        .expect(
            "enqueue_task('oci-index-child-ingest') must succeed — a 23514 check_violation \
             here means the effective jobs.kind CHECK (the newest migration that redefines \
             it) is missing the kind, or the composed idempotency key fails the charset CHECK",
        );
    let job_id = match outcome {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected Enqueued for a fresh key, got {other:?}"),
    };

    let row = sqlx::query(
        "SELECT kind, trigger_source, priority, idempotency_key, params \
         FROM public.jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_one(&pool)
    .await
    .expect("re-read enqueued oci-index-child-ingest row");
    let kind: String = row.get("kind");
    let trigger_source: String = row.get("trigger_source");
    let priority: i16 = row.get("priority");
    let stored_key: Option<String> = row.get("idempotency_key");
    let stored_params: serde_json::Value = row.get("params");
    assert_eq!(kind, KIND, "kind round-trip");
    assert_eq!(
        trigger_source, "ingest",
        "the row exists because an ingest observed an index declaring this child",
    );
    assert_eq!(
        priority, 0,
        "eager child ingest drains behind operator work"
    );
    assert_eq!(stored_key.as_deref(), Some(key.as_str()));
    assert_eq!(stored_params, params, "params round-trip");
}

/// A second enqueue under the same `(repository_id, child_digest)` key is
/// absorbed by `jobs_idempotency_key_uq` — the dedupe contract that stops two
/// indexes declaring the same child from both fetching it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn duplicate_child_row_is_absorbed_by_the_idempotency_key_index() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    let jobs = PgJobsRepository::new(pool.clone());
    let repository_id = Uuid::new_v4();
    let hex = "b".repeat(64);
    let params = serde_json::json!({
        "repository_id": repository_id,
        "requested_name": "dockerhub/library/nginx",
        "child_digest": format!("sha256:{hex}"),
    });
    let key = dedupe_key(repository_id, &hex);

    let first = jobs
        .enqueue_task(KIND, &params, None, 0i16, "ingest", Some(&key))
        .await
        .expect("first enqueue");
    let first_id = match first {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected Enqueued, got {other:?}"),
    };

    let second = jobs
        .enqueue_task(KIND, &params, None, 0i16, "ingest", Some(&key))
        .await
        .expect("second enqueue must be absorbed, not rejected");
    match second {
        EnqueueOutcome::Duplicate { existing_job_id } => {
            assert_eq!(
                existing_job_id, first_id,
                "the duplicate must resolve to the row already holding the key",
            );
        }
        other => panic!("expected Duplicate for a repeated key, got {other:?}"),
    }

    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.jobs WHERE idempotency_key = $1")
            .bind(key.as_str())
            .fetch_one(&pool)
            .await
            .expect("count rows under the key");
    assert_eq!(count, 1, "exactly one row may hold a given dedupe key");
}

/// A different repository asking for the same content is a DISTINCT unit of
/// work — ADR 0054 anchors the quarantine window per row, so the two must not
/// collapse onto one key.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_same_child_in_another_repository_is_a_separate_row() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    let jobs = PgJobsRepository::new(pool.clone());
    let hex = "c".repeat(64);
    let child_digest = format!("sha256:{hex}");

    let mut ids = Vec::new();
    for _ in 0..2 {
        let repository_id = Uuid::new_v4();
        let params = serde_json::json!({
            "repository_id": repository_id,
            "requested_name": "dockerhub/library/nginx",
            "child_digest": child_digest,
        });
        let key = dedupe_key(repository_id, &hex);
        match jobs
            .enqueue_task(KIND, &params, None, 0i16, "ingest", Some(&key))
            .await
            .expect("per-repository enqueue")
        {
            EnqueueOutcome::Enqueued { job_id } => ids.push(job_id),
            other => panic!("expected Enqueued for a per-repository key, got {other:?}"),
        }
    }
    assert_eq!(ids.len(), 2);
    assert_ne!(
        ids[0], ids[1],
        "each repository gets its own row (and therefore its own anchor)",
    );
}
