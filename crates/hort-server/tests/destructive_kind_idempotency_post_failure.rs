//! Destructive-task idempotency — post-failure same-day-reject test.
//!
//! Pins the ADR 0028 "key persists across failure" decision
//! structurally: a failed destructive job's `idempotency_key` claim
//! persists until the next UTC day, blocking same-day retry. The
//! CronJob schedule IS the retry mechanism — same-day recovery
//! requires an explicit `DELETE FROM jobs WHERE id = <failed_id>` by
//! the operator (out of scope here).
//!
//! **Why this test is load-bearing.** A regression here means a
//! future change has flipped the semantics from "claim persists
//! across failure" to "clear claim on failure". That flip
//! would defeat the third single-flight layer guarding the seal path
//! (ADR 0020, ADR 0028) — `seal_and_remove`'s unbounded internal wait
//! stays bounded *only* when the upstream gate is per-day, not
//! per-300s-window. If this test fails, the implementer MUST
//! re-litigate the ADR 0028 decision before changing the test; the
//! test is the structural pin on the decision, not an arbitrary
//! implementation detail.
//!
//! # Skip-when-no-DB convention
//!
//! Mirrors `task_use_case_enqueue_real_db.rs`: silently returns when
//! `DATABASE_URL` is unset so the suite stays green in dev. CI sets
//! the var for the integration tier.

#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serial_test::serial;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_adapters_postgres::{event_store::PgEventStore, jobs_repository::PgJobsRepository};
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::task_use_case::TaskUseCase;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::jobs_repository::{EnqueueOutcome, JobsRepository};
use hort_domain::types::IdempotencyKey;

/// Build an isolated test DB + run migrations. Returns `None` when
/// `DATABASE_URL` is unset (suite stays green in dev).
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    hort_adapters_postgres::test_support::isolated_db_from(&url).await
}

/// Seed a minimal `users` row so the `actor_id` FK on `jobs` is
/// satisfied.
async fn create_test_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.users (id, username, email, auth_provider, is_active) \
         VALUES ($1, $2, $3, 'local', true)",
    )
    .bind(id)
    .bind(format!("idem-post-fail-{}", id.simple()))
    .bind(format!("idem-post-fail-{}@example.test", id.simple()))
    .execute(pool)
    .await
    .expect("seed test user");
    id
}

/// `RbacEvaluator` that grants `Permission::AdminTaskInvoke` to the
/// `task-admin` claim. The `task:destructive` claim is checked
/// separately by `authorize_kind` against the caller's claim set.
fn rbac_with_task_invoke() -> Arc<ArcSwap<RbacEvaluator>> {
    let grant = PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec!["task-admin".into()]),
        repository_id: None,
        permission: Permission::AdminTaskInvoke,
        created_at: chrono::Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    };
    Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(vec![grant])))
}

fn destructive_caller(user_id: Uuid) -> CallerPrincipal {
    CallerPrincipal {
        user_id,
        external_id: "idem-post-failure".into(),
        username: "idem-post-failure".into(),
        email: "idem-post-failure@example.test".into(),
        claims: vec!["task-admin".into(), "task:destructive".into()],
        token_kind: None,
        issued_at: chrono::Utc::now(),
        token_cap: None,
    }
}

/// First enqueue succeeds; the row is then transitioned to terminal
/// `status='failed'` via raw SQL (simulating a worker terminal
/// failure with NO compensating clear of `idempotency_key`); a second
/// same-UTC-day enqueue with the **same** `Some(key)` MUST return
/// `EnqueueOutcome::Duplicate { existing_job_id }` pointing at the
/// failed row, AND no new row may be inserted.
#[tokio::test]
#[serial(hort_pg_db)]
async fn destructive_kind_idempotency_persists_across_worker_failure() {
    let Some(pool) = admin_pool().await else {
        // No DATABASE_URL — skip silently.
        return;
    };
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly");

    let user_id = create_test_user(&pool).await;
    let actor = destructive_caller(user_id);
    let kind = "retention-purge";
    let key = IdempotencyKey::try_from("cron:retention-purge:2026-06-04")
        .expect("server-derived shape always validates");

    let jobs: Arc<dyn JobsRepository> = Arc::new(PgJobsRepository::new(pool.clone()));
    let raw_events: Arc<dyn EventStore> = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new requires the immutability trigger from migrations"),
    );
    let events: Arc<EventStorePublisher> =
        Arc::new(EventStorePublisher::without_broadcast(raw_events));
    let use_case = TaskUseCase::new(
        Arc::clone(&jobs),
        Arc::clone(&events),
        rbac_with_task_invoke(),
    );

    // First enqueue — fresh row.
    let first_outcome = use_case
        .enqueue(&actor, kind, &serde_json::json!({}), Some(&key))
        .await
        .expect("first destructive enqueue must succeed");
    let first_id = match first_outcome {
        EnqueueOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected Enqueued on the first call, got {other:?}"),
    };

    // Simulate the worker terminally failing the job WITHOUT clearing
    // `idempotency_key` — this is the ADR 0028 persists-across-failure shape: the
    // claim persists across failure.
    let rows_affected = sqlx::query(
        "UPDATE public.jobs \
         SET status = 'failed', last_error = 'simulated terminal failure', \
             completed_at = now() \
         WHERE id = $1",
    )
    .bind(first_id)
    .execute(&pool)
    .await
    .expect("mark failed via raw SQL")
    .rows_affected();
    assert_eq!(rows_affected, 1, "exactly one row marked failed");

    // Second enqueue — same key, same UTC day. MUST dedup against the
    // failed row, NOT create a fresh one.
    let second_outcome = use_case
        .enqueue(&actor, kind, &serde_json::json!({}), Some(&key))
        .await
        .expect("second same-day destructive enqueue must succeed as Duplicate");
    let existing = match second_outcome {
        EnqueueOutcome::Duplicate { existing_job_id } => existing_job_id,
        EnqueueOutcome::Enqueued { job_id } => panic!(
            "REGRESSION: a failed destructive job's idempotency claim MUST persist until \
             the next UTC day (ADR 0028). Got a fresh Enqueued {{ job_id: {job_id} }} \
             instead of Duplicate. This means a future change has flipped decision (a) → (b) \
             (clear-on-failure). Re-litigate the ADR 0028 decision before changing this test.",
        ),
    };
    assert_eq!(
        existing, first_id,
        "Duplicate must point at the originally-failed row's id, not a sibling",
    );

    // Exactly one row exists for `(kind, idempotency_key)` — the failed
    // one. No new row was inserted by the second call.
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.jobs WHERE kind = $1 AND idempotency_key = $2",
    )
    .bind(kind)
    .bind(key.as_str())
    .fetch_one(&pool)
    .await
    .expect("count rows");
    assert_eq!(
        count, 1,
        "exactly one row must exist for the (kind, idempotency_key) pair after the deduped retry",
    );

    // The single surviving row is still the failed one (defence in
    // depth — pins that the second call did not somehow mutate it).
    let row =
        sqlx::query("SELECT id, status FROM public.jobs WHERE kind = $1 AND idempotency_key = $2")
            .bind(kind)
            .bind(key.as_str())
            .fetch_one(&pool)
            .await
            .expect("fetch the surviving row");
    let surviving_id: Uuid = row.get("id");
    let surviving_status: String = row.get("status");
    assert_eq!(surviving_id, first_id);
    assert_eq!(
        surviving_status, "failed",
        "the surviving row must remain in its failed state — second enqueue does not revive it",
    );
}
