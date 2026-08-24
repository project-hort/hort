//! `020_drop_artifacts_is_deleted.sql` migration tests.
//!
//! Asserts the schema invariants the migration ships with:
//!
//! 1. `artifacts.is_deleted` no longer exists.
//! 2. Both partial indexes Postgres dropped along with the column are
//!    recreated with the same key columns / `INCLUDE` payload, minus
//!    the predicate.
//! 3. The `package_version_status` servability read — the highest-QPS
//!    query in the serve path — still plans an index-only scan against
//!    the recreated covering index.
//!
//! Tests follow the convention in `migration_009_jobs_and_findings.rs` /
//! `migration_010_rescan_and_advisory.rs`: require `DATABASE_URL`; if
//! unset, every test early-returns so dev environments without a
//! database keep the suite green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test migration_020_drop_artifacts_is_deleted
//! ```

#![allow(clippy::expect_used)]

use std::env;

use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

/// Connect as the migration superuser; run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

// ---------------------------------------------------------------------------
// Test 1 — the column is gone.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn migration_020_is_deleted_column_does_not_exist() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'artifacts' \
           AND column_name = 'is_deleted')",
    )
    .fetch_one(&pool)
    .await
    .expect("probe artifacts.is_deleted column");
    assert!(
        !exists,
        "artifacts.is_deleted must not exist post-migration"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — both partial indexes are recreated with the predicate dropped
// and the same key / INCLUDE shape as migration 003.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn migration_020_recreated_indexes_match_original_shape_minus_predicate() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let name_idx_def: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'artifacts' \
           AND indexname = 'idx_artifacts_name_as_published'",
    )
    .fetch_one(&pool)
    .await
    .expect("probe idx_artifacts_name_as_published definition");
    assert!(
        name_idx_def.contains("(repository_id, name_as_published)"),
        "idx_artifacts_name_as_published must keep its original key columns; got: {name_idx_def}"
    );
    assert!(
        !name_idx_def.to_lowercase().contains("where"),
        "idx_artifacts_name_as_published must be a plain (non-partial) index now \
         the predicate selected the whole table; got: {name_idx_def}"
    );

    let covering_idx_def: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'artifacts' \
           AND indexname = 'idx_artifacts_repo_name_status_covering'",
    )
    .fetch_one(&pool)
    .await
    .expect("probe idx_artifacts_repo_name_status_covering definition");
    assert!(
        covering_idx_def.contains("(repository_id, name)"),
        "covering index must keep its original key columns; got: {covering_idx_def}"
    );
    assert!(
        covering_idx_def.contains("INCLUDE (version, quarantine_status)"),
        "covering index must keep its original INCLUDE payload; got: {covering_idx_def}"
    );
    assert!(
        !covering_idx_def.to_lowercase().contains("where"),
        "covering index must be a plain (non-partial) index now the predicate \
         selected the whole table; got: {covering_idx_def}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — the servability read (`package_version_status`'s query shape)
// still plans an index-only scan against the recreated covering index.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn migration_020_servability_read_plans_index_only_scan() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let repo_id = Uuid::new_v4();
    let key = format!("it-mig020-{}", repo_id.simple());
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $3,
               'npm'::repository_format,
               'hosted'::repository_type,
               'filesystem', $4,
               'local_only'::replication_priority
           )"#,
    )
    .bind(repo_id)
    .bind(&key)
    .bind(&key)
    .bind(format!("/tmp/{key}"))
    .execute(&pool)
    .await
    .expect("seed repository row");

    let id = Uuid::new_v4();
    let sha256 = format!("{}{}", id.simple(), id.simple());
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key,
               quarantine_status
           ) VALUES (
               $1, $2, 'leftpad', 'leftpad', '1.0.0', $3,
               0, $4, 'application/octet-stream', $4,
               'released'
           )"#,
    )
    .bind(id)
    .bind(repo_id)
    .bind(format!("simple/leftpad/{key}.tgz"))
    .bind(&sha256)
    .execute(&pool)
    .await
    .expect("seed artifact row");

    // A tiny seeded table gives the planner no reason to prefer an
    // index over a sequential scan on cost alone — disable the
    // alternatives so the plan reflects what the planner would choose
    // once the table is large enough for cost to matter, which is
    // exactly the condition this covering index exists for.
    // A dedicated connection (not `SET LOCAL`, which requires an open
    // transaction to take effect): this connection is held for the
    // rest of the test and then dropped, so scoping the session GUCs
    // to it cannot leak into any other test's connection.
    let mut conn = pool.acquire().await.expect("acquire connection");
    sqlx::query("SET enable_seqscan = off")
        .execute(&mut *conn)
        .await
        .expect("disable seqscan");
    sqlx::query("SET enable_bitmapscan = off")
        .execute(&mut *conn)
        .await
        .expect("disable bitmapscan");

    let plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN (FORMAT TEXT) \
         SELECT version, quarantine_status FROM artifacts \
         WHERE repository_id = $1 AND name = $2 AND version IS NOT NULL",
    )
    .bind(repo_id)
    .bind("leftpad")
    .fetch_all(&mut *conn)
    .await
    .expect("EXPLAIN package_version_status query shape");
    let plan_text = plan.join("\n");

    assert!(
        plan_text.contains("Index Only Scan")
            && plan_text.contains("idx_artifacts_repo_name_status_covering"),
        "the servability read must plan an index-only scan against the \
         covering index; got plan:\n{plan_text}"
    );
}
