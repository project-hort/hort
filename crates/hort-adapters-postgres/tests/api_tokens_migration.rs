//! `008_api_tokens.sql` migration tests.
//!
//! Asserts the schema invariants the migration ships with:
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
//! Plus `040_api_tokens_issued_via.sql`, whose column and backfill are
//! asserted here because the backfill can only be exercised against rows
//! that predate it:
//!
//! 5. `issued_via_backfill_marks_exactly_the_exchange_rows` — the real
//!    migration file re-applied over a fixture carrying the `/exchange`
//!    description, a near-miss, an operator-typed description and no
//!    description at all.
//! 6. `issued_via_check_rejects_an_unlisted_value` — the named CHECK.
//! 7. `issued_via_is_not_null_so_the_operator_predicate_cannot_drop_a_row`
//!    — why the column is NOT NULL rather than nullable.
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

use serial_test::serial;
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Executor, PgPool, Row};
use uuid::Uuid;

/// Connect as the migration superuser; run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
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
#[serial(hort_pg_db)]
async fn applies_on_baseline() {
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

    // The three expected indexes exist with their defined names.
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
#[serial(hort_pg_db)]
async fn idempotent_after_rollback() {
    // This test builds its own throwaway database rather than taking one
    // from `admin_pool()`. Its `DROP TABLE … CASCADE` + version-8-only
    // `_sqlx_migrations` rewind is globally destructive on whatever
    // database it runs against: the `CASCADE` collaterally drops every
    // FK that depends on `api_tokens` — e.g.
    // `subscriptions.created_by_token_id` — and rewinding only version 8
    // means dependent later migrations such as 013 are NOT recreated, so
    // the FK stays gone. That once reached a sibling
    // (`subscription_repo::api_tokens_id_delete_sets_null` saw the
    // CASCADE-dropped FK and failed). The test's purpose — "is
    // `008_api_tokens.sql` re-runnable from a baseline?" — is fully
    // self-contained and needs no shared state.
    //
    // A dedicated database is not on its own a reason to skip
    // `#[serial(hort_pg_db)]`: the `CREATE`/`DROP DATABASE` below and
    // the migration set's cluster-global `CREATE ROLE` are server-wide
    // work that collides with a concurrent sibling through the cluster,
    // whichever database each of them is connected to.
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
            .execute(sqlx::AssertSqlSafe(format!(
                "CREATE DATABASE \"{throwaway}\""
            )))
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
        .execute(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS \"{throwaway}\" WITH (FORCE)"
        )))
        .await
        .expect("drop the throwaway database");
    admin.close().await.ok();
}

// ---------------------------------------------------------------------------
// Acceptance bullet 2 — description length CHECK fires at 2 KB.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn description_length_check_rejects_2kb() {
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
#[serial(hort_pg_db)]
async fn kind_check_rejects_unknown_value() {
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

// ---------------------------------------------------------------------------
// `040_api_tokens_issued_via.sql` — the provenance column and its backfill.
// ---------------------------------------------------------------------------

/// Insert a row the way a pre-040 database held one: every column 008
/// defined, and nothing about where the token came from except the
/// free-text `description`. Returns the row id.
///
/// Deliberately raw SQL rather than `PgApiTokenRepository::insert` — the
/// adapter now always binds `issued_via`, which is precisely the state
/// this fixture must not be in.
async fn seed_pre_040_row(pool: &PgPool, user_id: Uuid, name: &str, description: Option<&str>) {
    sqlx::query(
        "INSERT INTO public.api_tokens \
            (user_id, name, description, kind, token_hash, token_prefix, \
             declared_permissions, created_by_user_id) \
         VALUES ($1, $2, $3, 'service_account', $4, $5, ARRAY['read']::text[], $1)",
    )
    .bind(user_id)
    .bind(name)
    .bind(description)
    .bind("$argon2id$v=19$m=19456,t=2,p=1$sentinel$sentinel")
    .bind(&Uuid::new_v4().simple().to_string()[..8])
    .execute(pool)
    .await
    .expect("seed a pre-040-shaped api_tokens row");
}

async fn issued_via_of(pool: &PgPool, name: &str) -> String {
    sqlx::query_scalar("SELECT issued_via FROM public.api_tokens WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("read back issued_via")
}

/// Rewind migration 040 on an isolated database: drop the column it
/// added and delete its bookkeeping row, so the next migrator run
/// re-applies the real migration file over rows that predate it.
///
/// This is the only way to exercise the backfill as shipped. Asserting a
/// copy of the `UPDATE` typed into the test would prove the test agrees
/// with itself, which is the failure mode the project has already paid
/// for elsewhere; here the statement under test is the one in
/// `migrations/040_api_tokens_issued_via.sql`.
///
/// The `DROP COLUMN` is safe only because the database is this test's
/// own (`isolated_db_from`), and it reaches no other table — unlike the
/// `DROP TABLE … CASCADE` in `idempotent_after_rollback`, which is why
/// that test hand-rolls its own database and this one does not need to.
async fn rewind_migration_040(pool: &PgPool) {
    pool.execute("ALTER TABLE public.api_tokens DROP COLUMN issued_via")
        .await
        .expect("drop the column 040 added");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 40")
        .execute(pool)
        .await
        .expect("rewind the _sqlx_migrations row for version 40");
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn issued_via_backfill_marks_exactly_the_exchange_rows() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;
    rewind_migration_040(&pool).await;

    // The one recoverable origin: the description the federation branch
    // of `/auth/token-exchange` writes.
    seed_pre_040_row(
        &pool,
        user_id,
        "exchange-row",
        Some("Federated via /exchange from 10.1.2.3 (client=gh-actions)"),
    )
    .await;
    // The near-miss, and not a hypothetical one: this is verbatim what
    // the CLI-session path writes. A `LIKE '%exchange%'` backfill would
    // absorb it and label a durable identity as exchange residue —
    // which drops it out of `issued_via <> 'federation_exchange'` and so
    // out of an operator's authority review, the one direction in which
    // being wrong is dangerous.
    seed_pre_040_row(
        &pool,
        user_id,
        "near-miss-row",
        Some("Issued via /exchange from 10.1.2.3"),
    )
    .await;
    // An operator who typed the word into a description.
    seed_pre_040_row(
        &pool,
        user_id,
        "operator-typed-row",
        Some("rotate before the next exchange window"),
    )
    .await;
    // A durable identity, and one with no description at all.
    seed_pre_040_row(
        &pool,
        user_id,
        "admin-cli-row",
        Some("Issued by hort-server admin issue-svc-token"),
    )
    .await;
    seed_pre_040_row(&pool, user_id, "no-description-row", None).await;

    // Re-apply: only version 40 is missing, so this runs the real
    // migration file — ADD COLUMN plus the backfill.
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migration 040 re-applies cleanly over pre-existing rows");

    assert_eq!(
        issued_via_of(&pool, "exchange-row").await,
        "federation_exchange",
        "the exact /exchange description text is the one origin the \
         backfill can recover"
    );
    for untouched in [
        "near-miss-row",
        "operator-typed-row",
        "admin-cli-row",
        "no-description-row",
    ] {
        assert_eq!(
            issued_via_of(&pool, untouched).await,
            "unknown",
            "{untouched} must keep the honest answer"
        );
    }
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn issued_via_check_rejects_an_unlisted_value() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let user_id = create_test_user(&pool).await;

    let err = sqlx::query(
        "INSERT INTO public.api_tokens \
            (user_id, name, kind, token_hash, token_prefix, \
             declared_permissions, created_by_user_id, issued_via) \
         VALUES ($1, $2, 'pat', $3, $4, ARRAY['read']::text[], $1, 'bogus')",
    )
    .bind(user_id)
    .bind("issued-via-check-test")
    .bind("$argon2id$v=19$m=19456,t=2,p=1$sentinel$sentinel")
    .bind("abcd1234")
    .execute(&pool)
    .await
    .expect_err("issued_via = 'bogus' must be rejected by the CHECK");

    let db_err = err
        .as_database_error()
        .expect("error must carry a Postgres-side code");
    assert_eq!(
        db_err.code().expect("Postgres error code present").as_ref(),
        "23514",
        "expected SQLSTATE 23514 (check_violation), got {err}"
    );
    assert!(
        db_err
            .constraint()
            .is_some_and(|c| c == "api_tokens_issued_via_check"),
        "the named constraint is what an operator sees in the error: {err}"
    );
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn issued_via_is_not_null_so_the_operator_predicate_cannot_drop_a_row() {
    // The column is NOT NULL on purpose. The authority query filters
    // `issued_via <> 'federation_exchange'`, and `NULL <> 'x'` is NULL,
    // not true — a nullable column would silently drop every row whose
    // origin is unrecorded out of the very review the column exists to
    // make possible.
    let Some(pool) = admin_pool().await else {
        return;
    };
    let nullable: bool = sqlx::query_scalar(
        "SELECT is_nullable = 'YES' FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'api_tokens' \
           AND column_name = 'issued_via'",
    )
    .fetch_one(&pool)
    .await
    .expect("probe issued_via nullability");
    assert!(!nullable, "api_tokens.issued_via must be NOT NULL");

    let user_id = create_test_user(&pool).await;
    let err = sqlx::query(
        "INSERT INTO public.api_tokens \
            (user_id, name, kind, token_hash, token_prefix, \
             declared_permissions, created_by_user_id, issued_via) \
         VALUES ($1, $2, 'pat', $3, $4, ARRAY['read']::text[], $1, NULL)",
    )
    .bind(user_id)
    .bind("issued-via-null-test")
    .bind("$argon2id$v=19$m=19456,t=2,p=1$sentinel$sentinel")
    .bind("abcd1234")
    .execute(&pool)
    .await
    .expect_err("an explicit NULL must be rejected");
    let db_err = err
        .as_database_error()
        .expect("error must carry a Postgres-side code");
    assert_eq!(
        db_err.code().expect("Postgres error code present").as_ref(),
        "23502",
        "expected SQLSTATE 23502 (not_null_violation), got {err}"
    );
}
