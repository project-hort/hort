//! Integration tests for the worker's boot-time schema gate
//! (`hort_worker::composition::assert_schema_current`).
//!
//! `hort-worker.service` sits on the same `Requires=hort-migrate.service`
//! chain as `hort-server.service`, so a release rollback has to get past
//! this gate too. Both binaries ask the same predicate
//! (`hort_config::schema_compat::SchemaCompatibility`), and these tests
//! pin that the worker therefore accepts and refuses exactly what
//! `hort-server`'s `migrate::assert_current` does — the server side is
//! covered in `hort-server/tests/migrate_assert_current.rs`.
//!
//! Requires a live PostgreSQL connection (the user must be a superuser:
//! each test creates a throwaway database to isolate `_sqlx_migrations`
//! state). Set `DATABASE_URL` to opt in:
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-worker --test schema_compat_boot
//! ```
//!
//! When `DATABASE_URL` is unset every test early-returns silently, so the
//! suite stays green in dev environments without a database.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::env;
use std::time::Duration;

use hort_worker::composition::assert_schema_current;
use sqlx::{Executor, PgPool};
use uuid::Uuid;

/// The worker embeds its own copy of the migration set (it must not
/// depend on `hort-server`), so the fixtures embed it a third time rather
/// than reaching across crates for it.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    PgPool::connect(&url).await.ok()
}

async fn create_temp_db(admin: &PgPool) -> (String, PgPool) {
    let suffix = Uuid::new_v4().simple().to_string();
    let db_name = format!("hort_test_worker_schema_{suffix}");
    // Identifier interpolation is safe here — `suffix` is a hex-only UUID
    // and the prefix is a literal.
    let create = format!("CREATE DATABASE \"{db_name}\"");
    admin
        .execute(sqlx::AssertSqlSafe(create))
        .await
        .expect("CREATE DATABASE (temp)");
    let url = temp_db_url(&db_name).expect("DATABASE_URL has a database segment");
    let pool = PgPool::connect(&url).await.expect("connect to temp DB");
    (db_name, pool)
}

async fn drop_temp_db(admin: &PgPool, db_name: &str, db_pool: PgPool) {
    db_pool.close().await;
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

/// Repoint `DATABASE_URL` at `db_name`, keeping everything before the
/// database segment. Query parameters are dropped along with the old
/// database name — the throwaway databases live on the same host with
/// the same credentials, so nothing else needs carrying over.
fn temp_db_url(db_name: &str) -> Option<String> {
    let admin_url = env::var("DATABASE_URL").ok()?;
    let without_query = admin_url.split('?').next()?;
    let (base, _old_db) = without_query.rsplit_once('/')?;
    Some(format!("{base}/{db_name}"))
}

fn embedded_versions() -> BTreeSet<i64> {
    MIGRATOR.iter().map(|m| m.version).collect()
}

fn newest_embedded_version() -> i64 {
    *embedded_versions()
        .iter()
        .next_back()
        .expect("migration set is non-empty at compile time")
}

fn second_newest_version() -> i64 {
    let versions = embedded_versions();
    let mut descending = versions.iter().rev();
    descending.next();
    *descending
        .next()
        .expect("the migration set has at least two versions")
}

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

// ---------------------------------------------------------------------------
// Tests
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

    assert_schema_current(&pool)
        .await
        .expect("an exactly-current schema must be accepted");

    drop_temp_db(&admin, &db_name, pool).await;
}

/// The binary-rollback case: the database was migrated by a newer release
/// and records a version this binary does not embed, strictly newer than
/// everything it does, recorded as an expansion. The worker must start.
#[tokio::test]
async fn newer_schema_is_supported() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");
    let newer = newest_embedded_version() + 1;
    insert_fake_migration(&pool, newer).await;
    insert_register_row(&pool, newer, None).await;

    assert_schema_current(&pool)
        .await
        .expect("a newer schema whose extra migrations are expansions must be accepted");

    drop_temp_db(&admin, &db_name, pool).await;
}

/// The register reaches the worker through the same predicate the server
/// asks, so a contraction the worker is too old for refuses its boot too —
/// with the migration and the version it would work from named.
#[tokio::test]
async fn newer_contraction_above_this_binary_bails() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");
    // `999.0.0` is unreachable from any real workspace version, so this
    // stays a refusal whatever the tree is versioned at.
    let newer = newest_embedded_version() + 1;
    insert_fake_migration(&pool, newer).await;
    insert_register_row(&pool, newer, Some("999.0.0")).await;

    let err = assert_schema_current(&pool)
        .await
        .expect_err("a contraction above this binary must bail");
    let msg = format!("{err:#}");
    assert!(msg.contains(&format!("migration {newer}")), "{msg}");
    assert!(msg.contains("999.0.0 or newer"), "{msg}");

    drop_temp_db(&admin, &db_name, pool).await;
}

/// Fail closed on the worker side too: an applied migration it does not
/// embed and the register does not cover is assumed to be a contraction.
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
    let newer = newest_embedded_version() + 1;
    insert_fake_migration(&pool, newer).await;

    let err = assert_schema_current(&pool)
        .await
        .expect_err("an unregistered newer migration must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("absent from the schema compatibility register"),
        "{msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

/// A schema behind the binary is still the ordinary upgrade path and must
/// still refuse, with the wording that names the corrective action.
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
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
        .bind(newest_embedded_version())
        .execute(&pool)
        .await
        .expect("delete the highest-version row");

    let err = assert_schema_current(&pool)
        .await
        .expect_err("a pending migration must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("schema version mismatch"),
        "unexpected error message: {msg}"
    );
    assert!(
        msg.contains("hort-server migrate"),
        "error must name the corrective action: {msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

/// A hole below the newest applied version is a broken history, not a
/// version skew, and is refused with the offending version named.
#[tokio::test]
async fn mid_sequence_hole_bails() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");
    let hole = second_newest_version();
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
        .bind(hole)
        .execute(&pool)
        .await
        .expect("delete a mid-sequence row");

    let err = assert_schema_current(&pool)
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

/// The bookkeeping table does not exist at all — the worker points the
/// operator at the migration step, in its own wording.
#[tokio::test]
async fn fresh_db_bails_with_table_missing() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    let err = assert_schema_current(&pool)
        .await
        .expect_err("fresh DB must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("_sqlx_migrations not found"),
        "unexpected error message: {msg}"
    );
    assert!(
        msg.contains("scanner worker"),
        "the worker keeps its own wording: {msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}
