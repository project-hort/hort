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
//! What each test covers (the branches of `assert_current`):
//!
//! 1. `fresh_db_bails_with_table_missing` — `_sqlx_migrations` does
//!    not exist; assert_current bails with the
//!    "_sqlx_migrations not found" message.
//! 2. `migrated_db_returns_ok` — every migration applied; assert_current
//!    returns Ok(()).
//! 3. `behind_schema_bails_with_mismatch` — highest-version row deleted;
//!    assert_current bails with `applied=N-1, binary expects=N`.
//! 4. `ahead_schema_is_supported` — fake row inserted at
//!    version=expected+1 and registered as an expansion; assert_current
//!    returns Ok(()), because a newer schema whose extra migrations
//!    removed nothing is a supported serving state under the
//!    expand/contract discipline (ADR 0030). This is the binary-rollback
//!    case.
//! 5. `many_newer_expansions_are_supported` — five releases of
//!    expansions ahead, all accepted: expansions do not accumulate into a
//!    refusal, which is exactly what a fixed release bound got wrong.
//! 6. `newer_contraction_above_this_binary_bails_and_names_the_way_out` —
//!    a registered contraction whose minimum this binary does not meet;
//!    the refusal names the migration and the version it would work from.
//! 7. `newer_migration_without_a_register_row_bails` — fail closed:
//!    silence is not evidence of an expansion.
//! 8. `unknown_version_below_the_waterline_bails` — fake row inserted
//!    *below* the newest embedded version; assert_current refuses and
//!    names it. A gap below the waterline is a broken history, not a
//!    version skew.
//! 9. `missing_mid_sequence_version_bails` — a shared-prefix row deleted
//!    while a newer one remains; assert_current refuses and names it.
//! 10. `permission_denied_bails_with_grant_message` — connect as a role
//!     that has no SELECT on `_sqlx_migrations`; assert_current bails
//!     with the "permission denied reading _sqlx_migrations" message.
//!
//! Each test creates a uniquely-named throwaway database (and, for #10,
//! a throwaway role) so concurrent `cargo test` runs don't collide on
//! shared schema state. Resources are dropped in test teardown.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
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
        .execute(sqlx::AssertSqlSafe(create))
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
        match admin.execute(sqlx::AssertSqlSafe(drop_sql.clone())).await {
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

/// Every version the binary embeds.
fn embedded_versions() -> BTreeSet<i64> {
    MIGRATOR.iter().map(|m| m.version).collect()
}

/// The second-highest embedded version — deleting its row leaves a hole
/// *below* a still-applied newer version, which is what distinguishes a
/// divergent history from a merely-behind schema.
fn second_newest_version() -> i64 {
    let versions = embedded_versions();
    let mut descending = versions.iter().rev();
    descending.next();
    *descending
        .next()
        .expect("the migration set has at least two versions")
}

/// A version the binary does not embed that nonetheless sits below the
/// newest one it does. Computed rather than hardcoded so a renumbering of
/// the migration sequence cannot silently turn this into a version the
/// binary actually embeds.
fn unused_version_below_waterline() -> i64 {
    let versions = embedded_versions();
    let newest = expected_version();
    (0..newest)
        .find(|v| !versions.contains(v))
        .expect("the migration sequence starts above 0, so 0 is never taken")
}

/// Record `version` in `schema_compat_register` the way a newer binary's
/// `migrate` would have: `None` for an expansion, `Some("X.Y.Z")` for a
/// contraction's `reference_removed_in`.
async fn insert_register_row(pool: &PgPool, version: i64, min_binary_version: Option<&str>) {
    sqlx::query("INSERT INTO schema_compat_register (version, min_binary_version) VALUES ($1, $2)")
        .bind(version)
        .bind(min_binary_version)
        .execute(pool)
        .await
        .expect("insert schema_compat_register row");
}

/// Record `version` in `_sqlx_migrations` without running anything — the
/// bookkeeping half of a migration another binary applied.
async fn insert_fake_migration(pool: &PgPool, version: i64) {
    sqlx::query(
        "INSERT INTO _sqlx_migrations \
         (version, description, installed_on, success, checksum, execution_time) \
         VALUES ($1, 'fake-migration', now(), true, decode('00', 'hex'), 0)",
    )
    .bind(version)
    .execute(pool)
    .await
    .expect("insert fake migration row");
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
// Branch 4 — applied strictly ahead of the embedded set (binary rollback)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ahead_schema_is_supported() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");

    // The binary-rollback shape: the database has been migrated by a
    // newer release, so it records a version this binary does not embed,
    // strictly newer than everything it does. The newer binary recorded
    // it as an expansion, which is what makes serving it safe — a
    // structurally-newer schema alone is no longer sufficient.
    let newer = expected_version() + 1;
    insert_fake_migration(&pool, newer).await;
    insert_register_row(&pool, newer, None).await;

    assert_current(&pool)
        .await
        .expect("a newer schema whose extra migrations are expansions must be accepted");

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Branch 5 — many newer expansions: the fixed-bound case the register
// exists to stop refusing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn many_newer_expansions_are_supported() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");

    // Five releases' worth of expansions ahead of this binary. Nothing
    // was removed, so there is nothing this binary can reference and
    // fail to find: it serves the schema regardless of the distance.
    for offset in 1..=5 {
        let version = expected_version() + offset;
        insert_fake_migration(&pool, version).await;
        insert_register_row(&pool, version, None).await;
    }

    assert_current(&pool)
        .await
        .expect("expansions do not accumulate into a refusal");

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Branch 6 — a newer contraction the binary is too old for
// ---------------------------------------------------------------------------

#[tokio::test]
async fn newer_contraction_above_this_binary_bails_and_names_the_way_out() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");

    // A future release removed an identifier this binary's code still
    // names, and recorded the release that stopped naming it. `999.0.0`
    // is unreachable from any real workspace version, so this stays a
    // refusal whatever the tree is versioned at.
    let newer = expected_version() + 1;
    insert_fake_migration(&pool, newer).await;
    insert_register_row(&pool, newer, Some("999.0.0")).await;

    let err = assert_current(&pool)
        .await
        .expect_err("a contraction above this binary must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&format!("migration {newer}")),
        "the refusal must name the migration that blocks the rollback: {msg}"
    );
    assert!(
        msg.contains("999.0.0 or newer"),
        "the refusal must name the version it would work from: {msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Branch 7 — a newer migration with no register row at all: fail closed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn newer_migration_without_a_register_row_bails() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");

    // Silence is not evidence of an expansion.
    let newer = expected_version() + 1;
    insert_fake_migration(&pool, newer).await;

    let err = assert_current(&pool)
        .await
        .expect_err("an unregistered newer migration must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&format!("migration {newer}")),
        "the refusal must name the migration: {msg}"
    );
    assert!(
        msg.contains("absent from the schema compatibility register"),
        "the refusal must say why it refused: {msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Branch 8 — divergence: an applied version below the embedded waterline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_version_below_the_waterline_bails() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");

    // A version the binary does not embed, sitting *below* the newest one
    // it does. Unlike branch 4 this is not a version skew — the shared
    // prefix is immutable (ADR 0022), so an unknown version inside it
    // means the histories genuinely diverged.
    let unknown = unused_version_below_waterline();
    insert_fake_migration(&pool, unknown).await;

    let err = assert_current(&pool)
        .await
        .expect_err("a below-the-waterline unknown version must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("divergent migration history"),
        "unexpected error message: {msg}"
    );
    assert!(
        msg.contains(&unknown.to_string()),
        "error must name the offending version {unknown}: {msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Branch 9 — divergence: an embedded version unapplied below the applied
// waterline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_mid_sequence_version_bails() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");

    // Delete a shared-prefix row while newer ones remain applied: the
    // database skipped a migration this binary embeds. Distinguishable
    // from branch 3 (behind schema) precisely because a newer version is
    // still recorded above the hole.
    let hole = second_newest_version();
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
        .bind(hole)
        .execute(&pool)
        .await
        .expect("delete a mid-sequence row");

    let err = assert_current(&pool)
        .await
        .expect_err("a mid-sequence hole must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("divergent migration history"),
        "unexpected error message: {msg}"
    );
    assert!(
        msg.contains(&hole.to_string()),
        "error must name the offending version {hole}: {msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Branch 10 — SELECT denied (42501)
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
    pool.execute(sqlx::AssertSqlSafe(create_role))
        .await
        .expect("CREATE USER (locked role)");
    let grant_connect = format!("GRANT CONNECT ON DATABASE \"{db_name}\" TO \"{role}\"");
    pool.execute(sqlx::AssertSqlSafe(grant_connect))
        .await
        .expect("GRANT CONNECT");
    let grant_usage = format!("GRANT USAGE ON SCHEMA public TO \"{role}\"");
    pool.execute(sqlx::AssertSqlSafe(grant_usage))
        .await
        .expect("GRANT USAGE");
    // Ensure the role explicitly cannot read the bookkeeping table —
    // belt-and-braces in case the test DB inherited a permissive
    // PUBLIC grant from template1.
    pool.execute("REVOKE ALL ON _sqlx_migrations FROM PUBLIC")
        .await
        .expect("REVOKE ALL FROM PUBLIC");
    let revoke = format!("REVOKE ALL ON _sqlx_migrations FROM \"{role}\"");
    pool.execute(sqlx::AssertSqlSafe(revoke))
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
    let _ = pool.execute(sqlx::AssertSqlSafe(drop_role)).await;
    drop_temp_db(&admin, &db_name, pool).await;
}
