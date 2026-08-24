//! `021_artifacts_soft_delete.sql` migration tests.
//!
//! Asserts the schema invariants the soft-delete migration ships with:
//!
//! 1. `artifacts.deleted_at` exists and is a nullable `timestamptz`.
//! 2. The table-wide `UNIQUE (repository_id, path)` constraint is gone
//!    and replaced by a **partial** unique index predicated on
//!    `deleted_at IS NULL` — the piece that lets a fresh ingest reuse a
//!    deleted artifact's path instead of colliding with the retained row.
//! 3. Both read-path indexes carry the same `deleted_at IS NULL`
//!    predicate, without losing their key columns or `INCLUDE` payload.
//!    The covering index's predicate is load-bearing for performance:
//!    every live read now filters `deleted_at IS NULL`, and the
//!    per-(package, version) servability query — the highest-QPS read in
//!    the index-serve path — only stays an index-only scan while the
//!    index predicate matches that filter.
//!
//! Tests follow the convention in the sibling migration suites: require
//! `DATABASE_URL`; if unset, every test early-returns so dev
//! environments without a database keep the suite green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test migration_021_artifacts_soft_delete
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

async fn index_def(pool: &PgPool, name: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'artifacts' AND indexname = $1",
    )
    .bind(name)
    .fetch_optional(pool)
    .await
    .expect("probe index definition")
}

/// Seed a repository row; returns its id.
async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-mig021-{}", id.simple());
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $2,
               'npm'::repository_format,
               'hosted'::repository_type,
               'filesystem', $3,
               'local_only'::replication_priority
           )"#,
    )
    .bind(id)
    .bind(&key)
    .bind(format!("/tmp/{key}"))
    .execute(pool)
    .await
    .expect("seed repository row");
    id
}

/// Insert an artifact at `path`. Returns the id, or the insert error.
async fn insert_artifact(pool: &PgPool, repo: Uuid, path: &str) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    let sha256 = format!("{}{}", id.simple(), id.simple());
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key
           ) VALUES (
               $1, $2, 'leftpad', 'leftpad', '1.0.0', $3,
               0, $4, 'application/octet-stream', $4
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(path)
    .bind(&sha256)
    .execute(pool)
    .await?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// Test 1 — the column exists, nullable, timestamptz.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn migration_021_deleted_at_column_is_a_nullable_timestamptz() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT data_type, is_nullable FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'artifacts' \
           AND column_name = 'deleted_at'",
    )
    .fetch_optional(&pool)
    .await
    .expect("probe artifacts.deleted_at column");

    let (data_type, is_nullable) = row.expect("artifacts.deleted_at must exist post-migration");
    assert_eq!(data_type, "timestamp with time zone");
    assert_eq!(
        is_nullable, "YES",
        "NULL is the live state — the column must be nullable"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — table-wide path uniqueness is gone, replaced by a partial index.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn migration_021_path_uniqueness_is_partial_on_live_rows() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let old_constraint: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint \
         WHERE conname = 'artifacts_repository_id_path_key')",
    )
    .fetch_one(&pool)
    .await
    .expect("probe the old constraint");
    assert!(
        !old_constraint,
        "the table-wide UNIQUE (repository_id, path) constraint must be gone — \
         it is what kept a retained deleted row occupying its path"
    );

    let def = index_def(&pool, "artifacts_repository_id_path_live_key")
        .await
        .expect("the partial unique index must exist");
    assert!(
        def.contains("UNIQUE INDEX"),
        "path uniqueness must survive as a unique index; got: {def}"
    );
    assert!(
        def.contains("(repository_id, path)"),
        "the index must key on (repository_id, path); got: {def}"
    );
    assert!(
        def.contains("deleted_at IS NULL"),
        "uniqueness must be scoped to live rows only; got: {def}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — the partial index enforces uniqueness among live rows and
// admits a re-ingest at a deleted artifact's path.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn migration_021_partial_index_frees_a_deleted_artifacts_path() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let path = "leftpad/-/leftpad-1.0.0.tgz";

    let first = insert_artifact(&pool, repo, path)
        .await
        .expect("first insert at the path");

    // While the first row is live, a second at the same path is rejected.
    let err = insert_artifact(&pool, repo, path)
        .await
        .expect_err("two live rows may not share a path");
    assert!(
        err.to_string().to_lowercase().contains("unique"),
        "expected a unique-violation, got {err}"
    );

    // Soft-delete it, then re-ingest at the same path.
    sqlx::query("UPDATE public.artifacts SET deleted_at = now() WHERE id = $1")
        .bind(first)
        .execute(&pool)
        .await
        .expect("soft-delete the first row");

    let second = insert_artifact(&pool, repo, path)
        .await
        .expect("a deleted row must not reserve its path");
    assert_ne!(second, first);

    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM public.artifacts \
         WHERE repository_id = $1 AND path = $2 AND deleted_at IS NULL",
    )
    .bind(repo)
    .bind(path)
    .fetch_one(&pool)
    .await
    .expect("count live rows at the path");
    assert_eq!(live, 1, "exactly one live row at the path");
}

// ---------------------------------------------------------------------------
// Test 4 — both read-path indexes are re-predicated without losing shape.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn migration_021_read_path_indexes_are_partial_on_live_rows() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let name_idx = index_def(&pool, "idx_artifacts_name_as_published")
        .await
        .expect("name index must exist");
    assert!(
        name_idx.contains("(repository_id, name_as_published)"),
        "key columns must survive the rebuild; got: {name_idx}"
    );
    assert!(
        name_idx.contains("deleted_at IS NULL"),
        "the name index must match its read's filter; got: {name_idx}"
    );

    let covering = index_def(&pool, "idx_artifacts_repo_name_status_covering")
        .await
        .expect("covering index must exist");
    assert!(
        covering.contains("(repository_id, name)"),
        "key columns must survive the rebuild; got: {covering}"
    );
    assert!(
        covering.contains("INCLUDE (version, quarantine_status)"),
        "the INCLUDE payload is what keeps the servability read index-only; got: {covering}"
    );
    assert!(
        covering.contains("deleted_at IS NULL"),
        "the covering index must match the servability read's filter, or that \
         read degrades to a heap fetch per matched row; got: {covering}"
    );
}
