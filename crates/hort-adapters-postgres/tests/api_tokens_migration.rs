//! `008_api_tokens.sql` migration tests.
//!
//! Asserts the §3 schema invariants the migration ships with:
//!
//! 1. `applies_on_baseline` — fresh DB → all migrations through
//!    008 run cleanly, table + indexes exist.
//! 2. `idempotent_after_rollback` — apply, drop, re-apply (in a fresh
//!    DB-state shape via `_sqlx_migrations` rewind) — succeeds. Pins
//!    that the SQL is re-runnable on a baseline-only DB.
//! 3. `description_length_check_rejects_2kb` — INSERT with
//!    `description = repeat('x', 2048)` fails with the
//!    `api_tokens_description_length_check` constraint name in the error
//!    (GDPR description-length cap).
//! 4. `kind_check_rejects_unknown_value` — INSERT with `kind = 'bogus'`
//!    fails the inline kind CHECK constraint.
//!
//! These tests follow the project convention (mirrored from
//! `events_role_hardening.rs`): require `DATABASE_URL` to be set; if
//! unset, every test early-returns `Ok` so dev environments without a
//! database keep the suite green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test api_tokens_migration
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::sync::OnceLock;

use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Executor, PgPool, Row};
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

/// Per-binary serialization gate for the three shared-DB tests
/// `applies_on_init23_baseline`, `description_length_check_rejects_2kb`
/// and `kind_check_rejects_unknown_value`. They probe / INSERT
/// `public.api_tokens` on the shared test database; this per-binary
/// lock keeps them from racing each other under cargo's intra-binary
/// test parallelism.
///
/// `idempotent_after_rollback` deliberately does NOT take this lock and
/// does NOT touch the shared database. Its `DROP TABLE … CASCADE` plus
/// version-8-only `_sqlx_migrations` rewind is globally destructive: the
/// `CASCADE` drops FKs that other tables depend on (for example
/// `subscriptions.created_by_token_id`), and only version 8 is
/// re-applied, so dependent later migrations are not recreated. A
/// binary-scoped lock cannot contain that, because cargo runs test
/// binaries in parallel — the destructive test would corrupt the shared
/// schema other test binaries use concurrently (this was a real
/// cross-binary CI flake). It is therefore isolated to its own
/// throwaway database, not merely locked.
fn serial_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Acquire the per-binary serial lock for the test's duration. Held
/// until the returned guard is dropped at the end of the test body.
async fn lock_serial() -> MutexGuard<'static, ()> {
    serial_lock().lock().await
}

/// Connect as the migration superuser; run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");
    Some(pool)
}

/// Build connect options pointed at a specific database, derived from
/// `DATABASE_URL` (same host/user/password, different dbname). Used by
/// `idempotent_after_rollback` to reach the `postgres` maintenance DB
/// (for `CREATE`/`DROP DATABASE`) and its own throwaway DB.
fn opts_for_db(base_url: &str, db: &str) -> PgConnectOptions {
    base_url
        .parse::<PgConnectOptions>()
        .expect("DATABASE_URL parses as Postgres connect options")
        .database(db)
}

/// Insert a minimal-but-valid `users` row and return the id. Several
/// tests need a `created_by_user_id` / `user_id` to satisfy the FKs;
/// rather than depending on the seeded admin (which is provisioned at
/// runtime, not in migrations), each test spawns its own throwaway
/// user. Caller is responsible for the cascade-delete on cleanup
/// (or simply leaving the row — UUID-named throwaways don't collide).
async fn create_test_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.users (id, username, email, auth_provider, is_active) \
         VALUES ($1, $2, $3, 'local', true)",
    )
    .bind(id)
    .bind(format!("apitoken_test_{}", id.simple()))
    .bind(format!("apitoken_test_{}@example.test", id.simple()))
    .execute(pool)
    .await
    .expect("seed test user");
    id
}

// ---------------------------------------------------------------------------
// Acceptance bullet 1 — migration applies cleanly on a fresh baseline.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn applies_on_baseline() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };

    // Table exists in the public schema after migrations 001..008.
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
                        WHERE table_schema = 'public' AND table_name = 'api_tokens')",
    )
    .fetch_one(&pool)
    .await
    .expect("probe api_tokens existence");
    assert!(
        table_exists,
        "api_tokens table must exist after running through 008"
    );

    // The three §3 indexes exist with the spec-defined names.
    let mut index_rows = sqlx::query(
        "SELECT indexname FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'api_tokens' \
         ORDER BY indexname",
    )
    .fetch_all(&pool)
    .await
    .expect("probe api_tokens indexes");
    let mut indexes: Vec<String> = index_rows
        .iter_mut()
        .map(|r| r.get::<String, _>("indexname"))
        .collect();
    indexes.sort();

    for required in [
        "idx_api_tokens_prefix",
        "idx_api_tokens_revoked",
        "idx_api_tokens_user",
    ] {
        assert!(
            indexes.iter().any(|i| i == required),
            "expected index {required} to exist; saw {indexes:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance bullet 5 — idempotent on re-application after rollback.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn idempotent_after_rollback() {
    // NO shared `lock_serial()` / `admin_pool()`. This test's
    // `DROP TABLE … CASCADE` + version-8-only `_sqlx_migrations` rewind
    // is globally destructive on whatever database it runs against (the
    // `CASCADE` collaterally drops every FK that depends on
    // `api_tokens` — e.g. `subscriptions.created_by_token_id` — and
    // rewinding only version 8 means dependent later migrations such as
    // 013 are NOT recreated, so the FK stays gone). Run it against a
    // dedicated throwaway database so it can never corrupt the shared
    // test DB that sibling test binaries use concurrently (cargo runs
    // test binaries in parallel — this was a real cross-binary flake:
    // `subscription_repo::api_tokens_id_delete_sets_null` saw the
    // CASCADE-dropped FK and failed). The test's purpose — "is
    // `008_api_tokens.sql` re-runnable from a baseline?" — is fully
    // self-contained and needs no shared state.
    let Some(base_url) = env::var("DATABASE_URL").ok() else {
        return;
    };
    let throwaway = format!("apitoken_rollback_{}", Uuid::new_v4().simple());

    // `CREATE`/`DROP DATABASE` cannot run in a transaction and cannot
    // target the connected database — use a maintenance connection to
    // `postgres`.
    let admin_opts = opts_for_db(&base_url, "postgres");
    {
        let mut admin = sqlx::PgConnection::connect_with(&admin_opts)
            .await
            .expect("connect to the `postgres` maintenance database");
        (&mut admin)
            .execute(format!("CREATE DATABASE \"{throwaway}\"").as_str())
            .await
            .expect("create throwaway database for the rollback test");
        admin.close().await.ok();
    }

    let pool = PgPool::connect_with(opts_for_db(&base_url, &throwaway))
        .await
        .expect("connect to the throwaway database");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the throwaway DB");

    // Simulate the rollback: DROP the table the migration created, and
    // rewind the `_sqlx_migrations` bookkeeping row for version 8 so the
    // migrator will re-apply it on the next run. This pins that the
    // migration's SQL is re-runnable on a baseline-only DB — i.e. the
    // CREATE TABLE / CREATE INDEX statements are correct standalone,
    // not just as a delta from some specific intermediate state.
    pool.execute("DROP TABLE IF EXISTS public.api_tokens CASCADE")
        .await
        .expect("DROP api_tokens for rollback simulation");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 8")
        .execute(&pool)
        .await
        .expect("rewind _sqlx_migrations row for version 8");

    // Re-apply — must succeed cleanly.
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations re-apply cleanly after rollback simulation");

    // Sanity — the table is back.
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
                        WHERE table_schema = 'public' AND table_name = 'api_tokens')",
    )
    .fetch_one(&pool)
    .await
    .expect("probe api_tokens existence after re-apply");
    assert!(
        table_exists,
        "api_tokens table must exist again after re-apply"
    );

    pool.close().await;

    // Best-effort teardown. A panic above leaks one uniquely-named
    // throwaway DB — harmless (UUID-named, never collides; CI uses a
    // fresh postgres service per pipeline) — and it can NEVER corrupt
    // the shared DB, which is the entire point of the isolation.
    let mut admin = sqlx::PgConnection::connect_with(&admin_opts)
        .await
        .expect("reconnect to drop the throwaway database");
    (&mut admin)
        .execute(format!("DROP DATABASE IF EXISTS \"{throwaway}\" WITH (FORCE)").as_str())
        .await
        .expect("drop the throwaway database");
    admin.close().await.ok();
}

// ---------------------------------------------------------------------------
// Acceptance bullet 2 — description length CHECK fires at 2 KB.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn description_length_check_rejects_2kb() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;

    let two_kb_description = "x".repeat(2048);

    let err = sqlx::query(
        "INSERT INTO public.api_tokens \
            (user_id, name, description, kind, token_hash, token_prefix, \
             declared_permissions, created_by_user_id) \
         VALUES ($1, $2, $3, 'pat', $4, $5, ARRAY['read']::text[], $1)",
    )
    .bind(user_id)
    .bind("description-length-test")
    .bind(&two_kb_description)
    .bind("$argon2id$v=19$m=19456,t=2,p=1$sentinel$sentinel")
    .bind("abcd1234")
    .execute(&pool)
    .await
    .expect_err("2 KB description must be rejected by the length CHECK");

    let db_err = err
        .as_database_error()
        .expect("error must carry a Postgres-side code");
    let code = db_err.code().expect("Postgres error code present");
    assert_eq!(
        code.as_ref(),
        "23514",
        "expected SQLSTATE 23514 (check_violation), got {code}: {err}"
    );
    let msg = db_err.message();
    assert!(
        msg.contains("api_tokens_description_length_check"),
        "error must name the constraint api_tokens_description_length_check; got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Acceptance — kind CHECK rejects unknown values (defensive cousin of B2's
// schema-verbatim requirement; pins that the inline kind CHECK is wired up).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kind_check_rejects_unknown_value() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;

    let err = sqlx::query(
        "INSERT INTO public.api_tokens \
            (user_id, name, kind, token_hash, token_prefix, \
             declared_permissions, created_by_user_id) \
         VALUES ($1, $2, 'bogus', $3, $4, ARRAY['read']::text[], $1)",
    )
    .bind(user_id)
    .bind("kind-check-test")
    .bind("$argon2id$v=19$m=19456,t=2,p=1$sentinel$sentinel")
    .bind("abcd1234")
    .execute(&pool)
    .await
    .expect_err("kind = 'bogus' must be rejected by the inline CHECK");

    let db_err = err
        .as_database_error()
        .expect("error must carry a Postgres-side code");
    let code = db_err.code().expect("Postgres error code present");
    assert_eq!(
        code.as_ref(),
        "23514",
        "expected SQLSTATE 23514 (check_violation), got {code}: {err}"
    );
}
