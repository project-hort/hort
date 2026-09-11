//! Integration tests for the migrate runner's half of the
//! schema-compatibility gate (`hort_server::migrate::run`).
//!
//! `hort-server.service` and `hort-worker.service` require
//! `hort-migrate.service`, and the chart runs the same subcommand as a
//! `pre-upgrade` hook, so every start re-runs `migrate` with the
//! *installed* binary. Rolling a release back therefore has to get past
//! this gate before it ever reaches the serve-path assertion — which is
//! why both consume the same predicate. The serve-path half is covered in
//! `migrate_assert_current.rs`.
//!
//! What each test covers:
//!
//! 1. `newer_schema_applies_nothing_and_succeeds` — the database records a
//!    version this binary does not embed, strictly newer than everything
//!    it does. `run` succeeds and applies nothing.
//! 2. `newer_schema_still_verifies_the_shared_prefix_checksums` — the same
//!    state, but with a shared-prefix checksum tampered with. `run` must
//!    still fail: the tolerance that lets the rollback through suppresses
//!    exactly one error (a version the binary does not embed) and never
//!    touches checksum validation.
//! 3. `unknown_version_below_the_waterline_refuses` — a version the binary
//!    does not embed, sitting below the newest one it does. `run` refuses
//!    before applying anything and names the offender.
//! 4. `mid_sequence_hole_refuses` — an embedded version missing from the
//!    bookkeeping table while a newer one is recorded. Same refusal.
//! 5. `migrating_a_fresh_database_registers_every_applied_migration` /
//!    `re_running_migrate_leaves_the_register_unchanged` /
//!    `an_upgrade_backfills_every_embedded_migration` — the register write:
//!    one row per migration the binary embeds, carrying the oldest binary
//!    version it tolerates, written once and never rewritten, and
//!    backfilled for whatever an older, pre-register binary already
//!    applied.
//! 6. `a_newer_contraction_refuses_the_migrate_gate_too` /
//!    `an_unregistered_newer_migration_refuses_the_migrate_gate` — a
//!    structurally-newer schema is not enough: a migration ahead that
//!    removed something, or that records nothing at all, refuses.
//! 7. `both_gates_agree_on_a_registered_expansion_and_on_a_contraction` —
//!    the property the whole predicate exists for, over the register
//!    layer: `migrate` and the serve-path assertion reach the same
//!    verdict, so a rollback is never half-admitted.
//!
//! These tests require a live PostgreSQL connection (the user must be a
//! superuser: each test creates a throwaway database to isolate
//! `_sqlx_migrations` state). Set `DATABASE_URL` to opt in:
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-server --test migrate_schema_compat
//! ```
//!
//! When `DATABASE_URL` is unset every test early-returns silently, matching
//! the convention in `migrate_assert_current.rs`, so the suite stays green
//! in dev environments without a database.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::time::Duration;

use hort_config::schema_compat::{register_from_rows, schema_rollback_floor, SchemaRollbackFloor};
use hort_server::migrate::{assert_current, run as migrate_run, MIGRATOR};
use sqlx::{Executor, PgPool};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixture helpers — mirrors `migrate_assert_current.rs`.
// ---------------------------------------------------------------------------

async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    PgPool::connect(&url).await.ok()
}

async fn create_temp_db(admin: &PgPool) -> (String, PgPool) {
    let suffix = Uuid::new_v4().simple().to_string();
    let db_name = format!("hort_test_schema_compat_{suffix}");
    // Identifier interpolation is safe here — `suffix` is a hex-only UUID
    // and the prefix is a literal.
    let create = format!("CREATE DATABASE \"{db_name}\"");
    admin
        .execute(sqlx::AssertSqlSafe(create))
        .await
        .expect("CREATE DATABASE (temp)");
    let url = temp_db_url(&db_name).expect("DATABASE_URL parses");
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

fn temp_db_url(db_name: &str) -> Option<String> {
    let admin_url = env::var("DATABASE_URL").ok()?;
    let parsed = url::Url::parse(&admin_url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(5432);
    let user = parsed.username();
    let pw = parsed.password()?;
    Some(format!("postgresql://{user}:{pw}@{host}:{port}/{db_name}"))
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

/// A version the binary does not embed that sits below the newest one it
/// does. Computed, not hardcoded, so a renumbering cannot turn it into a
/// version the binary actually embeds.
fn unused_version_below_waterline() -> i64 {
    let versions = embedded_versions();
    let newest = newest_embedded_version();
    (0..newest)
        .find(|v| !versions.contains(v))
        .expect("the migration sequence starts above 0, so 0 is never taken")
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

async fn applied_versions(pool: &PgPool) -> BTreeSet<i64> {
    sqlx::query_scalar::<_, i64>("SELECT version FROM _sqlx_migrations")
        .fetch_all(pool)
        .await
        .expect("read applied versions")
        .into_iter()
        .collect()
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

/// The whole register, as `version -> min_binary_version`.
async fn register_rows(pool: &PgPool) -> BTreeMap<i64, Option<String>> {
    sqlx::query_as::<_, (i64, Option<String>)>(
        "SELECT version, min_binary_version FROM schema_compat_register",
    )
    .fetch_all(pool)
    .await
    .expect("read schema_compat_register")
    .into_iter()
    .collect()
}

// ---------------------------------------------------------------------------
// Supported — the binary-rollback shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn newer_schema_applies_nothing_and_succeeds() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");
    let future_version = newest_embedded_version() + 1;
    insert_fake_migration(&pool, future_version).await;
    insert_register_row(&pool, future_version, None).await;
    let before = applied_versions(&pool).await;

    migrate_run(&pool)
        .await
        .expect("a schema newer than the binary must migrate cleanly");

    assert_eq!(
        applied_versions(&pool).await,
        before,
        "nothing may be applied when every embedded migration is already recorded"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

/// The tolerance that lets the rollback through suppresses exactly one
/// error — a recorded version the binary does not embed. Checksum
/// validation of the versions present in both sets is untouched, and this
/// pins that: a tampered shared-prefix checksum must still abort the run.
#[tokio::test]
async fn newer_schema_still_verifies_the_shared_prefix_checksums() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");
    let future_version = newest_embedded_version() + 1;
    insert_fake_migration(&pool, future_version).await;
    insert_register_row(&pool, future_version, None).await;

    let tampered = second_newest_version();
    sqlx::query("UPDATE _sqlx_migrations SET checksum = decode('00', 'hex') WHERE version = $1")
        .bind(tampered)
        .execute(&pool)
        .await
        .expect("tamper with a shared-prefix checksum");

    let err = migrate_run(&pool)
        .await
        .expect_err("a shared-prefix checksum divergence must still abort");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&tampered.to_string()),
        "error must name the mismatched version {tampered}: {msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Divergent — refuse in both directions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_version_below_the_waterline_refuses() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run(&pool)
        .await
        .expect("migrations apply cleanly to fresh DB");
    let unknown = unused_version_below_waterline();
    insert_fake_migration(&pool, unknown).await;

    let err = migrate_run(&pool)
        .await
        .expect_err("a below-the-waterline unknown version must be refused");
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

#[tokio::test]
async fn mid_sequence_hole_refuses() {
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

    let err = migrate_run(&pool)
        .await
        .expect_err("a mid-sequence hole must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("divergent migration history"),
        "unexpected error message: {msg}"
    );
    assert!(
        msg.contains(&hole.to_string()),
        "error must name the offending version {hole}: {msg}"
    );
    assert!(
        !applied_versions(&pool).await.contains(&hole),
        "the refusal must come before anything is applied"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// The register write — every applied migration gets its row, carrying the
// oldest binary version it tolerates.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migrating_a_fresh_database_registers_every_applied_migration() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    migrate_run(&pool)
        .await
        .expect("a fresh database must migrate cleanly");

    let register = register_rows(&pool).await;
    assert_eq!(
        register.keys().copied().collect::<BTreeSet<_>>(),
        embedded_versions(),
        "every migration this run applied owes the register a row"
    );

    // The contraction the manifest declares carries its
    // `reference_removed_in`; everything else removed nothing and
    // records NULL. `020_drop_artifacts_is_deleted.sql` is the incident
    // exemplar the expand/contract policy exists for.
    assert_eq!(
        register.get(&20),
        Some(&Some("0.12.0".to_string())),
        "a declared contraction records the oldest binary version it tolerates"
    );
    assert_eq!(
        register.get(&21),
        Some(&None),
        "a migration the manifest does not name removed nothing"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

/// Re-running `migrate` against an up-to-date database applies nothing and
/// writes nothing — the rows are already there and an applied migration's
/// contraction status is frozen (ADR 0022), so there is nothing to update.
#[tokio::test]
async fn re_running_migrate_leaves_the_register_unchanged() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    migrate_run(&pool).await.expect("first migrate");
    let first = register_rows(&pool).await;
    migrate_run(&pool).await.expect("second migrate");

    assert_eq!(register_rows(&pool).await, first);

    drop_temp_db(&admin, &db_name, pool).await;
}

/// A database migrated by an older binary that predates the register: the
/// table exists (this binary embeds the migration that creates it) but
/// carries no rows for the migrations already applied. The upgrade still
/// runs, applies nothing (the schema is already current), but backfills a
/// row for every migration this binary embeds — closing both the crash
/// window and the inspection gap on a database that was never migrated by a
/// register-carrying binary before.
#[tokio::test]
async fn an_upgrade_backfills_every_embedded_migration() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    migrate_run(&pool).await.expect("migrate");
    // Rewind the register to the state an older, pre-register binary would
    // have left: no rows at all, for a database whose migrations were all
    // applied before the register existed.
    sqlx::query("DELETE FROM schema_compat_register")
        .execute(&pool)
        .await
        .expect("clear the register");

    migrate_run(&pool)
        .await
        .expect("an up-to-date schema must still migrate cleanly");

    let register = register_rows(&pool).await;
    assert_eq!(
        register.keys().copied().collect::<BTreeSet<_>>(),
        embedded_versions(),
        "a run that applies nothing still backfills a row for every migration it embeds"
    );

    let applied = applied_versions(&pool).await;
    assert_eq!(
        schema_rollback_floor(&applied, &register_from_rows(register)),
        SchemaRollbackFloor::Version("0.12.0".to_string()),
        "the backfill closes the inspection gap: an upgraded database reports a rollback \
         floor instead of `indeterminate`"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// Intolerable — the register turns a structurally-newer schema into a
// refusal when one of the migrations ahead removed something.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_newer_contraction_refuses_the_migrate_gate_too() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    migrate_run(&pool).await.expect("migrate");
    // `999.0.0` is unreachable from any real workspace version, so this
    // stays a refusal whatever the tree is versioned at.
    let future_version = newest_embedded_version() + 1;
    insert_fake_migration(&pool, future_version).await;
    insert_register_row(&pool, future_version, Some("999.0.0")).await;

    let err = migrate_run(&pool)
        .await
        .expect_err("a contraction above this binary must be refused");
    let msg = format!("{err:#}");
    assert!(msg.contains("refusing to migrate"), "{msg}");
    assert!(
        msg.contains(&format!("migration {future_version}")),
        "the refusal must name the migration that blocks the rollback: {msg}"
    );
    assert!(
        msg.contains("999.0.0 or newer"),
        "the refusal must name the version it would work from: {msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

#[tokio::test]
async fn an_unregistered_newer_migration_refuses_the_migrate_gate() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    migrate_run(&pool).await.expect("migrate");
    let future_version = newest_embedded_version() + 1;
    insert_fake_migration(&pool, future_version).await;

    let err = migrate_run(&pool)
        .await
        .expect_err("an unregistered newer migration must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("absent from the schema compatibility register"),
        "{msg}"
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

/// The gates agree. Whatever `migrate` accepts, the serve-path assertion
/// accepts; whatever it refuses, the assertion refuses. One gate passing
/// while the other refuses is what makes a rollback impossible, so the
/// register must not reintroduce that split.
#[tokio::test]
async fn both_gates_agree_on_a_registered_expansion_and_on_a_contraction() {
    let Some(admin) = admin_pool().await else {
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    migrate_run(&pool).await.expect("migrate");

    let expansion = newest_embedded_version() + 1;
    insert_fake_migration(&pool, expansion).await;
    insert_register_row(&pool, expansion, None).await;
    migrate_run(&pool)
        .await
        .expect("migrate accepts a registered expansion ahead");
    assert_current(&pool)
        .await
        .expect("serve accepts the same schema");

    let contraction = expansion + 1;
    insert_fake_migration(&pool, contraction).await;
    insert_register_row(&pool, contraction, Some("999.0.0")).await;
    let migrate_err = migrate_run(&pool)
        .await
        .expect_err("migrate refuses a contraction above this binary");
    let serve_err = assert_current(&pool)
        .await
        .expect_err("serve refuses the same schema");
    for msg in [format!("{migrate_err:#}"), format!("{serve_err:#}")] {
        assert!(msg.contains(&format!("migration {contraction}")), "{msg}");
        assert!(msg.contains("999.0.0 or newer"), "{msg}");
    }

    drop_temp_db(&admin, &db_name, pool).await;
}
