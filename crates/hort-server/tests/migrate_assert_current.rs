//! Integration tests for `hort_server::migrate::assert_current`
//! (least-privilege runtime, ADR 0009).
//!
//! These tests require a live PostgreSQL connection (the runtime user
//! must be a superuser, because each test creates a throwaway database
//! to isolate `_sqlx_migrations` state, and one test creates a
//! throwaway role to exercise the permission-denied branch). Set
//! `DATABASE_URL` to opt in:
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-server --test migrate_assert_current
//! ```
//!
//! When `DATABASE_URL` is unset every test early-returns silently
//! (matches the convention in `hort_adapters_postgres::events_role_hardening`)
//! so the suite stays green in dev environments without a database.
//!
//! What each test covers (the five branches of `assert_current`):
//!
//! 1. `fresh_db_bails_with_table_missing` — `_sqlx_migrations` does
//!    not exist; assert_current bails with the
//!    "_sqlx_migrations not found" message.
//! 2. `migrated_db_returns_ok` — every migration applied; assert_current
//!    returns Ok(()).
//! 3. `behind_schema_bails_with_mismatch` — highest-version row deleted;
//!    assert_current bails with `applied=N-1, binary expects=N`.
//! 4. `ahead_schema_bails_with_mismatch` — fake row inserted at
//!    version=expected+1; assert_current bails with
//!    `applied=N+1, binary expects=N`.
//! 5. `permission_denied_bails_with_grant_message` — connect as a role
//!    that has no SELECT on `_sqlx_migrations`; assert_current bails
//!    with the "permission denied reading _sqlx_migrations" message.
//!
//! Each test creates a uniquely-named throwaway database (and, for #5,
//! a throwaway role) so concurrent `cargo test` runs don't collide on
//! shared schema state. Resources are dropped in test teardown.

#![allow(clippy::expect_used)]

use std::env;
use std::time::Duration;

use hort_server::migrate::{assert_current, MIGRATOR};
use sqlx::{Executor, PgPool};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Connect as the superuser pointed at by `DATABASE_URL`. Returns
/// `None` when the env var is unset so the suite stays green in
/// dev environments without a database (mirrors the
/// `events_role_hardening` skip-when-no-DB convention).
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    PgPool::connect(&url).await.ok()
}

/// Create a uniquely-named throwaway database under the same host as
/// `DATABASE_URL`, and return `(db_name, pool_to_that_db)`. The
/// caller is responsible for `drop_temp_db` at end-of-test.
async fn create_temp_db(admin: &PgPool) -> (String, PgPool) {
    let suffix = Uuid::new_v4().simple().to_string();
    let db_name = format!("hort_test_assert_current_{suffix}");
    // Identifier interpolation is safe here — `suffix` is a
    // hex-only UUID and the prefix is a literal.
    let create = format!("CREATE DATABASE \"{db_name}\"");
    admin
        .execute(create.as_str())
        .await
        .expect("CREATE DATABASE (temp)");
    let url = temp_db_url(&db_name).expect("DATABASE_URL parses");
    let pool = PgPool::connect(&url).await.expect("connect to temp DB");
    (db_name, pool)
}

/// Close the temp pool, then drop the database. Drop failures are
/// logged but not propagated (a leaked DB is preferable to masking
/// the real test failure).
async fn drop_temp_db(admin: &PgPool, db_name: &str, db_pool: PgPool) {
    db_pool.close().await;
    // Postgres rejects DROP DATABASE while connections linger; pool
    // close above is awaited, but the server-side teardown is async.
    // A short retry loop keeps the test deterministic without
    // flakiness on busy CI hosts.
    let drop_sql = format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)");
    for attempt in 0..5 {
        match admin.execute(drop_sql.as_str()).await {
            Ok(_) => return,
            Err(e) if attempt < 4 => {
                eprintln!("DROP DATABASE {db_name} attempt {attempt} failed: {e}; retrying");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                eprintln!("warning: failed to drop temp DB {db_name}: {e}");
                return;
            }
        }
    }
}

/// Build a connection URL targeting `db_name` against the same host
/// `DATABASE_URL` points at. Returns `None` if `DATABASE_URL` is unset
/// or not parseable.
fn temp_db_url(db_name: &str) -> Option<String> {
    let admin_url = env::var("DATABASE_URL").ok()?;
    let parsed = url::Url::parse(&admin_url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(5432);
    let user = parsed.username();
    let pw = parsed.password()?;
    Some(format!("postgresql://{user}:{pw}@{host}:{port}/{db_name}"))
}

/// The version the binary's MIGRATOR expects to be applied (the max
/// version in the embedded migration set). All branch-comparison
/// tests pin against this value.
fn expected_version() -> i64 {
    MIGRATOR
        .iter()
        .map(|m| m.version)
        .max()
        .expect("migration set is non-empty at compile time")
}

// ---------------------------------------------------------------------------
// Branch 1 — table missing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fresh_db_bails_with_table_missing() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    // Fresh DB has no `_sqlx_migrations` table. assert_current must
    // bail with the operator-actionable message — the message
    // wording is part of the contract; tests assert on it.
    let err = assert_current(&pool).await.expect_err("fresh DB must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("_sqlx_migrations not found"),
        "unexpected error message: {msg}"
    );
    assert!(
        msg.contains("hort-server migrate"),
        "error message must name the corrective action: {msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Branch 2 — migrated, equal versions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migrated_db_returns_ok() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");

    assert_current(&pool)
        .await
        .expect("migrated DB must return Ok");

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Branch 3 — applied < expected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn behind_schema_bails_with_mismatch() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");

    let expected = expected_version();
    // Simulate "binary newer than schema" by deleting the highest
    // applied version row — `MAX(version)` then reports the next
    // version DOWN. NOT necessarily `expected - 1`: the migration
    // sequence on disk is non-contiguous (the `f8ecab57` collapse
    // folded 012/014/015/016 back into 009 in place per pre-1.0
    // discipline), so deleting 13 leaves 11 as MAX, not 12. Read the
    // new MAX from the DB to stay correct under any future collapse.
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
        .bind(expected)
        .execute(&pool)
        .await
        .expect("delete highest-version row");
    let applied: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .expect("read new MAX version after deletion");

    let err = assert_current(&pool)
        .await
        .expect_err("behind schema must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("schema version mismatch"),
        "unexpected error message: {msg}"
    );
    assert!(
        msg.contains(&format!("applied={applied}")),
        "error must report applied={applied}: {msg}"
    );
    assert!(
        msg.contains(&format!("expects={expected}")),
        "error must report expects={expected}: {msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Branch 4 — applied > expected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ahead_schema_bails_with_mismatch() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");

    let expected = expected_version();
    let ahead = expected + 1;
    // Simulate "rolling-upgrade misordering" (an old binary booting
    // against a DB that a newer binary has already migrated) by
    // inserting a fake row at expected + 1.
    sqlx::query(
        "INSERT INTO _sqlx_migrations \
         (version, description, installed_on, success, checksum, execution_time) \
         VALUES ($1, 'fake-future-migration', now(), true, decode('00', 'hex'), 0)",
    )
    .bind(ahead)
    .execute(&pool)
    .await
    .expect("insert fake-future-migration row");

    let err = assert_current(&pool)
        .await
        .expect_err("ahead schema must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("schema version mismatch"),
        "unexpected error message: {msg}"
    );
    assert!(
        msg.contains(&format!("applied={ahead}")),
        "error must report applied={ahead}: {msg}"
    );
    assert!(
        msg.contains(&format!("expects={expected}")),
        "error must report expects={expected}: {msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Branch 5 — SELECT denied (42501)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn permission_denied_bails_with_grant_message() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");

    // Mint a throwaway role that has CONNECT + USAGE but lacks
    // SELECT on `_sqlx_migrations`. The default GRANT SELECT chain
    // does not extend to the bookkeeping table without an explicit
    // grant (the least-privilege runtime role, ADR 0009 — this is the
    // exact gap the assertion's 42501 branch surfaces).
    let suffix = Uuid::new_v4().simple().to_string();
    let role = format!("hort_test_locked_{suffix}");
    let password = format!("pw_{suffix}");
    let create_role =
        format!("CREATE USER \"{role}\" WITH NOSUPERUSER LOGIN PASSWORD '{password}'");
    pool.execute(create_role.as_str())
        .await
        .expect("CREATE USER (locked role)");
    let grant_connect = format!("GRANT CONNECT ON DATABASE \"{db_name}\" TO \"{role}\"");
    pool.execute(grant_connect.as_str())
        .await
        .expect("GRANT CONNECT");
    let grant_usage = format!("GRANT USAGE ON SCHEMA public TO \"{role}\"");
    pool.execute(grant_usage.as_str())
        .await
        .expect("GRANT USAGE");
    // Ensure the role explicitly cannot read the bookkeeping table —
    // belt-and-braces in case the test DB inherited a permissive
    // PUBLIC grant from template1.
    pool.execute("REVOKE ALL ON _sqlx_migrations FROM PUBLIC")
        .await
        .expect("REVOKE ALL FROM PUBLIC");
    let revoke = format!("REVOKE ALL ON _sqlx_migrations FROM \"{role}\"");
    pool.execute(revoke.as_str())
        .await
        .expect("REVOKE ALL on _sqlx_migrations from locked role");

    // Build a pool as the locked role and call assert_current.
    let admin_url = env::var("DATABASE_URL").expect("DATABASE_URL set in this branch");
    let parsed = url::Url::parse(&admin_url).expect("DATABASE_URL parses");
    let host = parsed.host_str().expect("DATABASE_URL has host");
    let port = parsed.port().unwrap_or(5432);
    let locked_url = format!("postgresql://{role}:{password}@{host}:{port}/{db_name}");
    let locked_pool = PgPool::connect(&locked_url)
        .await
        .expect("connect as locked role");

    let err = assert_current(&locked_pool)
        .await
        .expect_err("permission-denied role must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("permission denied reading _sqlx_migrations"),
        "unexpected error message: {msg}"
    );
    assert!(
        msg.contains("postgres-roles.md"),
        "error must point operators at the how-to: {msg}"
    );

    locked_pool.close().await;
    let drop_role = format!("DROP USER IF EXISTS \"{role}\"");
    let _ = pool.execute(drop_role.as_str()).await;
    drop_temp_db(&admin, &db_name, pool).await;
}
