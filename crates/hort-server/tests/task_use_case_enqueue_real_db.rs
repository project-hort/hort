//! Integration test — `TaskUseCase::enqueue` for every value in
//! `VALID_TASK_KINDS` against a real PostgreSQL instance.
//!
//! # Why this test exists
//!
//! The bug behind a rotation-smoke 500-spiral was a
//! literal mismatch between the use case's `enqueue_task(...,
//! trigger_source = "api")` call and the SQL CHECK constraint on
//! `jobs.trigger_source`, which only accepts
//! `'manual' | 'cron' | 'advisory' | 'ingest'`. The pre-existing
//! `migration_009_creates_jobs_table_with_all_kinds` integration test
//! exercised the SQL path with raw INSERTs, so it could not catch the
//! literal mismatch — only a path through the real use case ↔ real
//! adapter ↔ real DB can.
//!
//! This test walks every kind in `VALID_TASK_KINDS` through
//! `TaskUseCase::enqueue`, asserts the row lands successfully, and
//! re-reads it to pin both the persisted `trigger_source` and the
//! `actor_id` FK satisfaction.
//!
//! # Coverage scope
//!
//! - Every kind in `VALID_TASK_KINDS` enqueues without error.
//! - The persisted row's `trigger_source` is the literal the use case
//!   passes (`"manual"`). Changing it back to anything not in the
//!   CHECK allow-list re-breaks this test.
//! - `actor_id` references a real `users` row (FK satisfaction).
//!
//! # Skip-when-no-DB convention
//!
//! Mirrors `events_role_hardening` and `migrate_assert_current`:
//! every test early-returns silently when `DATABASE_URL` is unset, so
//! the suite stays green in dev environments without a database. CI
//! sets `DATABASE_URL` and runs the integration tier (Tier 2).
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-server --test task_use_case_enqueue_real_db
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;

use arc_swap::ArcSwap;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_adapters_postgres::{event_store::PgEventStore, jobs_repository::PgJobsRepository};
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::task_use_case::TaskUseCase;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::events::VALID_TASK_KINDS;
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::jobs_repository::JobsRepository;

/// Connect to the URL pointed at by `DATABASE_URL`. Returns `None` when
/// the env var is unset so the suite stays green without a DB.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");
    Some(pool)
}

/// Insert a minimal-but-valid `users` row and return its id. Mirrors
/// the hort-adapters-postgres api-tokens migration test's
/// `create_test_user`. The `actor_id`
/// the use case passes through to `enqueue_task` references this row.
async fn create_test_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.users (id, username, email, auth_provider, is_active) \
         VALUES ($1, $2, $3, 'local', true)",
    )
    .bind(id)
    .bind(format!("task-uc-it-{}", id.simple()))
    .bind(format!("task-uc-it-{}@example.test", id.simple()))
    .execute(pool)
    .await
    .expect("seed test user");
    id
}

/// Build an `RbacEvaluator` that grants `Permission::AdminTaskInvoke`
/// to the `"task-admin"` role. Mirrors the in-crate unit-test helper
/// of the same name.
fn rbac_with_task_invoke() -> Arc<ArcSwap<RbacEvaluator>> {
    // Claim-based RBAC (ADR 0012) — global AdminTaskInvoke grant bound
    // to the `task-admin` claim (there is no role-keyed grant map; a
    // principal carrying the `task-admin` claim matches).
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

/// Walk every value in `VALID_TASK_KINDS` through
/// `TaskUseCase::enqueue` against a real DB and confirm:
/// 1. each enqueue succeeds (no SQL CHECK / FK violation);
/// 2. the persisted row carries `trigger_source = 'manual'`;
/// 3. `actor_id` resolves the FK against the seeded test user.
///
/// If a future change broadens or narrows `VALID_TASK_KINDS`, the loop
/// implicitly covers the new set. If a future change re-introduces a
/// trigger_source literal absent from the SQL CHECK (the historical
/// "api" regression), every iteration fails with a 23514 violation.
#[tokio::test]
async fn enqueue_accepts_every_valid_kind() {
    let Some(pool) = admin_pool().await else {
        // No DATABASE_URL — silently skip (matches the convention used
        // by `events_role_hardening` and `migrate_assert_current`).
        return;
    };

    let user_id = create_test_user(&pool).await;

    let jobs: Arc<dyn JobsRepository> = Arc::new(PgJobsRepository::new(pool.clone()));
    let raw_events: Arc<dyn EventStore> = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new (immutability trigger must be installed by migrations)"),
    );
    // Every use case's event-store dependency is wrapped in
    // `EventStorePublisher` (see
    // `docs/architecture/explanation/event-notifications.md`); this
    // integration test does not exercise the notification broadcast, so
    // the non-broadcasting wrapper is correct.
    let events: Arc<EventStorePublisher> =
        Arc::new(EventStorePublisher::without_broadcast(raw_events));
    let rbac = rbac_with_task_invoke();
    let use_case = TaskUseCase::new(Arc::clone(&jobs), Arc::clone(&events), rbac);

    let actor = CallerPrincipal {
        user_id,
        external_id: "task-uc-it".into(),
        username: "task-uc-it".into(),
        email: "task-uc-it@example.test".into(),
        // Claim-based RBAC (ADR 0012) — the `task-admin` claim matches
        // the `rbac_with_task_invoke` grant (claims, not roles).
        // `task:destructive` is the
        // additional claim the destructive-kind
        // gate (ADR 0028) requires on top of `Permission::AdminTaskInvoke` for the
        // destructive kinds in `VALID_TASK_KINDS` (`retention-evaluate`,
        // `retention-purge`, `eventstore-archive`); this test asserts a
        // sufficiently-privileged actor can enqueue *every* valid kind,
        // so it must carry it.
        claims: vec!["task-admin".into(), "task:destructive".into()],
        token_kind: None,
        issued_at: chrono::Utc::now(),
        token_cap: None,
    };

    assert!(
        !VALID_TASK_KINDS.is_empty(),
        "VALID_TASK_KINDS must be non-empty — the loop below would silently pass"
    );

    for &kind in VALID_TASK_KINDS {
        let params = serde_json::json!({});
        let outcome = use_case
            .enqueue(&actor, kind, &params, None)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "TaskUseCase::enqueue must succeed for kind={kind:?} (most likely cause: \
                     SQL CHECK on jobs.kind or jobs.trigger_source rejected the literal the \
                     use case passes — see migration 009's CHECK constraint and the \
                     trigger_source rationale in task_use_case.rs:128). Underlying error: {e}",
                )
            });
        let job_id = match outcome {
            hort_domain::ports::jobs_repository::EnqueueOutcome::Enqueued { job_id } => job_id,
            other => panic!("expected Enqueued for None-key path on kind={kind:?}, got {other:?}"),
        };

        // Re-read the row and pin the persisted shape. trigger_source
        // is the constant the bug landed on; kind round-trips the
        // loop variable.
        let row =
            sqlx::query("SELECT kind, trigger_source, actor_id FROM public.jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&pool)
                .await
                .expect("re-read enqueued jobs row");

        let persisted_kind: String = row.get("kind");
        let persisted_trigger: String = row.get("trigger_source");
        let persisted_actor: Option<Uuid> = row.get("actor_id");

        assert_eq!(persisted_kind, kind, "persisted kind round-trip");
        assert_eq!(
            persisted_trigger, "manual",
            "trigger_source must be a literal accepted by the migration 009 CHECK; \
             this assertion catches the historical \"api\" regression",
        );
        assert_eq!(
            persisted_actor,
            Some(user_id),
            "actor_id must reference the seeded test user (FK satisfaction)",
        );
    }
}
