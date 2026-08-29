//! Integration tests for the runtime fleet fence
//! (`hort_server::migrate::evaluate_fleet_fence` /
//! `hort_server::migrate::gate_on_fleet_fence`, ADR 0030 amendment (c)).
//!
//! # What this pins
//!
//! `expand_contract_guard` (build-time, `crates/hort-app/tests/`) stops a
//! contraction from being *authored* in the same release that removed the
//! last code reference. It has no runtime effect: an operator who runs
//! `hort-server migrate` while a previous release's binaries are still
//! connected can still apply a legitimately-deferred contraction straight
//! into that old fleet's face. This suite drives the fence that closes
//! that operational-ordering gap against a real Postgres, using the
//! workspace's *actual* migration set and the *actual* checked-in
//! `migrations/CONTRACTIONS.toml` (versions 9, 14, 20 are declared
//! contractions there) — no fixtures needed, since the manifest already
//! gives us both a contraction and several expand-only migrations to test
//! against.
//!
//! 1. `pending_contraction_with_older_fleet_blocks_and_names_offender` —
//!    a pending contraction + an older-version hort-shaped connection ⇒
//!    the fence blocks and names the offender; `gate_on_fleet_fence`
//!    refuses without the override and proceeds with it.
//! 2. `pending_contraction_with_unversioned_hort_client_blocks` — same,
//!    but the other connection is hort-shaped with NO version segment
//!    (predates this fence) ⇒ fail-closed, treated as older.
//! 3. `pending_contraction_with_no_older_fleet_does_not_block` — a
//!    pending contraction but no other hort-shaped connection at all ⇒
//!    not blocked; `migrate::run` then applies cleanly.
//! 4. `expand_only_pending_set_is_never_fenced` — pending set has no
//!    contraction, even with an older-version connection present ⇒ never
//!    blocked; `migrate::run` applies cleanly.
//! 5. `older_fleet_member_on_a_different_database_does_not_block` — an
//!    older-version hort-shaped connection exists, but on a *different*
//!    database in the same cluster ⇒ the fence must not treat it as an
//!    offender (`pg_stat_activity` is cluster-wide; the contraction is not).
//! 6. `both_identity_schemes_stamp_application_name_visible_in_pg_stat_activity`
//!    — `hort_server::pg_identity::connect_options` (the real
//!    `hort-server` production connect path) AND the `hort-worker`
//!    identity shape (built from the same shared, already-unit-tested
//!    `hort_config::pg_identity::pg_application_name` primitive
//!    `hort_worker::pg_identity::connect_options` also calls) both show
//!    up correctly in `pg_stat_activity`. `hort-worker`'s own wrapper is
//!    a 3-line call into that same shared primitive and is unit-tested
//!    (DB-free) in its own crate (`crates/hort-worker/src/pg_identity.rs`)
//!    — cross-crate-depending on the `hort-worker` binary crate from a
//!    `hort-server` test purely to re-prove an identical 3-line wrapper
//!    would be test-only coupling between the two composition roots with
//!    no additional coverage value.
//!
//! # `#[serial(hort_pg_db)]`
//!
//! Mandatory here even though every test below uses its own throwaway
//! database (`create_temp_db`, mirroring `migrate_assert_current.rs`):
//! `pg_stat_activity` is a **cluster-wide** view, not scoped to one
//! database, so two of these tests running concurrently could see each
//! other's simulated fleet connections. Honors the project's DB-test
//! parallel-safety contract (see CLAUDE.md → "DB-backed test isolation").
//!
//! # Skip-when-no-DB
//!
//! Every test early-returns (with a `tracing`-free `eprintln!`, mirroring
//! `migrate_assert_current.rs`) when `DATABASE_URL` is unset, so the suite
//! stays green in dev environments without a database. CI sets
//! `DATABASE_URL` and runs the integration tier (Tier 2).

#![allow(clippy::expect_used)]

use std::env;
use std::str::FromStr;
use std::time::Duration;

use hort_server::migrate::{
    evaluate_fleet_fence, gate_on_fleet_fence, run as migrate_run, MIGRATOR,
};
use serial_test::serial;
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use uuid::Uuid;

/// This test binary's own `CARGO_PKG_VERSION` — identical to
/// `hort-server`'s (workspace-inherited `version.workspace = true`), so
/// it is the correct "current version" side of the fence's comparison.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Fixture helpers — mirrors `migrate_assert_current.rs`.
// ---------------------------------------------------------------------------

/// Connect as the superuser pointed at by `DATABASE_URL`. Returns `None`
/// when the env var is unset so the suite stays green without a database.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    PgPool::connect(&url).await.ok()
}

/// Create a uniquely-named throwaway database and return
/// `(db_name, pool_to_that_db)`. Caller drops it via `drop_temp_db`.
async fn create_temp_db(admin: &PgPool) -> (String, PgPool) {
    let suffix = Uuid::new_v4().simple().to_string();
    let db_name = format!("hort_test_fleet_fence_{suffix}");
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

/// Open (and keep alive — callers hold the returned connection) a
/// throwaway connection against `db_name` with `application_name` set to
/// `application_name`. Simulates one fleet member for the duration the
/// caller holds it.
async fn connect_with_application_name(db_name: &str, application_name: &str) -> PgConnection {
    let opts = PgConnectOptions::from_str(&temp_db_url(db_name).expect("DATABASE_URL parses"))
        .expect("temp DB URL parses as PgConnectOptions")
        .application_name(application_name);
    PgConnection::connect_with(&opts)
        .await
        .expect("connect as simulated fleet member")
}

/// A migration version, strictly below the lowest declared contraction
/// (9), so `MIGRATOR.run_to(BEFORE_FIRST_CONTRACTION, ..)` leaves every
/// declared contraction (9, 14, 20) pending.
const BEFORE_FIRST_CONTRACTION: i64 = 8;

/// The highest migration version below the workspace's current max —
/// `MIGRATOR.run_to(EXPAND_ONLY_TARGET, ..)` leaves exactly the last
/// migration pending. Computed from `MIGRATOR` itself (not hardcoded) so
/// this stays correct as new expand-only migrations are appended.
fn expand_only_target() -> i64 {
    let max = MIGRATOR
        .iter()
        .map(|m| m.version)
        .max()
        .expect("migration set is non-empty at compile time");
    max - 1
}

// ---------------------------------------------------------------------------
// 1 — pending contraction + older fleet member: blocked, override works.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn pending_contraction_with_older_fleet_blocks_and_names_offender() {
    let Some(admin) = admin_pool().await else {
        eprintln!("DATABASE_URL unset; skipping");
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run_to(BEFORE_FIRST_CONTRACTION, &pool)
        .await
        .expect("partial migration run succeeds");

    let older_version_name = "hort-server/0.11.0";
    let _older_conn = connect_with_application_name(&db_name, older_version_name).await;

    let fence = evaluate_fleet_fence(&pool, CURRENT_VERSION)
        .await
        .expect("fence evaluates");
    assert!(
        fence.blocked,
        "a pending contraction with an older fleet member connected must block"
    );
    assert!(
        fence
            .offenders
            .iter()
            .any(|o| o.contains(older_version_name)),
        "offenders must name {older_version_name:?}: {:?}",
        fence.offenders
    );

    let refusal = gate_on_fleet_fence(&fence, false).expect_err("must refuse without override");
    assert!(refusal.contains(older_version_name), "refusal: {refusal}");
    assert!(
        refusal.contains("--allow-running-fleet"),
        "refusal must name the override: {refusal}"
    );
    gate_on_fleet_fence(&fence, true).expect("--allow-running-fleet must override the block");

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// 2 — pending contraction + unversioned hort-shaped client: fail-closed.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn pending_contraction_with_unversioned_hort_client_blocks_fail_closed() {
    let Some(admin) = admin_pool().await else {
        eprintln!("DATABASE_URL unset; skipping");
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run_to(BEFORE_FIRST_CONTRACTION, &pool)
        .await
        .expect("partial migration run succeeds");

    // Hort-shaped, but no `/version` segment — a client that predates the
    // fence's identity scheme. Must be treated as older (fail-closed),
    // not skipped as unparseable.
    let unversioned_name = "hort-server";
    let _legacy_conn = connect_with_application_name(&db_name, unversioned_name).await;

    let fence = evaluate_fleet_fence(&pool, CURRENT_VERSION)
        .await
        .expect("fence evaluates");
    assert!(
        fence.blocked,
        "an unversioned hort-shaped client must fail-closed as older"
    );
    assert!(
        fence.offenders.iter().any(|o| o.contains(unversioned_name)),
        "offenders must name the unversioned client: {:?}",
        fence.offenders
    );

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// 3 — pending contraction, no older fleet: not blocked, migrate applies.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn pending_contraction_with_no_older_fleet_does_not_block() {
    let Some(admin) = admin_pool().await else {
        eprintln!("DATABASE_URL unset; skipping");
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run_to(BEFORE_FIRST_CONTRACTION, &pool)
        .await
        .expect("partial migration run succeeds");

    let fence = evaluate_fleet_fence(&pool, CURRENT_VERSION)
        .await
        .expect("fence evaluates");
    assert!(
        !fence.blocked,
        "no other hort-shaped connection is present; the fence must not block: {:?}",
        fence.offenders
    );
    gate_on_fleet_fence(&fence, false).expect("not blocked ⇒ always Ok");

    migrate_run(&pool)
        .await
        .expect("migrate::run applies the remaining (contraction-inclusive) set cleanly");

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// 4 — expand-only pending set: never fenced, even with an older fleet.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn expand_only_pending_set_is_never_fenced() {
    let Some(admin) = admin_pool().await else {
        eprintln!("DATABASE_URL unset; skipping");
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;

    let target = expand_only_target();
    MIGRATOR
        .run_to(target, &pool)
        .await
        .expect("partial migration run to just below the top succeeds");

    // An older-version connection IS present — proves the pending set's
    // shape (no contraction), not the absence of fleet members, is what
    // holds this fence open.
    let _older_conn = connect_with_application_name(&db_name, "hort-server/0.1.0").await;

    let fence = evaluate_fleet_fence(&pool, CURRENT_VERSION)
        .await
        .expect("fence evaluates");
    assert!(
        !fence.blocked,
        "an expand-only pending set must never be fenced: {:?}",
        fence.offenders
    );

    migrate_run(&pool)
        .await
        .expect("migrate::run applies the last expand-only migration cleanly");

    drop_temp_db(&admin, &db_name, pool).await;
}

// ---------------------------------------------------------------------------
// 5 — an older fleet member connected to a DIFFERENT database is unrelated.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn older_fleet_member_on_a_different_database_does_not_block() {
    let Some(admin) = admin_pool().await else {
        eprintln!("DATABASE_URL unset; skipping");
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;
    // A second, unrelated database in the same cluster — simulates a
    // co-hosted deployment (a different hort instance, a staging DB, a CI
    // database) whose fleet is irrelevant to this database's contraction.
    let (other_db_name, other_pool) = create_temp_db(&admin).await;

    MIGRATOR
        .run_to(BEFORE_FIRST_CONTRACTION, &pool)
        .await
        .expect("partial migration run succeeds");

    let older_version_name = "hort-server/0.11.0";
    let _older_conn_elsewhere =
        connect_with_application_name(&other_db_name, older_version_name).await;

    let fence = evaluate_fleet_fence(&pool, CURRENT_VERSION)
        .await
        .expect("fence evaluates");
    assert!(
        !fence.blocked,
        "an older fleet member connected to a different database must not block: {:?}",
        fence.offenders
    );

    drop_temp_db(&admin, &db_name, pool).await;
    drop_temp_db(&admin, &other_db_name, other_pool).await;
}

// ---------------------------------------------------------------------------
// 6 — both identity schemes are visible in pg_stat_activity.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn both_identity_schemes_stamp_application_name_visible_in_pg_stat_activity() {
    let Some(admin) = admin_pool().await else {
        eprintln!("DATABASE_URL unset; skipping");
        return;
    };
    let (db_name, pool) = create_temp_db(&admin).await;
    let url = temp_db_url(&db_name).expect("DATABASE_URL parses");

    // The real `hort-server` production connect path.
    let server_opts =
        hort_server::pg_identity::connect_options(&url).expect("hort-server connect_options");
    let server_conn = PgConnection::connect_with(&server_opts)
        .await
        .expect("connect as hort-server");

    // The `hort-worker` identity shape, built from the same shared
    // `hort_config::pg_identity` primitive `hort_worker::pg_identity`
    // wraps — see the module doc comment for why this test does not
    // depend on the `hort-worker` crate directly.
    let worker_name =
        hort_config::pg_identity::pg_application_name(hort_config::pg_identity::WORKER_ROLE);
    let worker_opts = PgConnectOptions::from_str(&url)
        .expect("temp DB URL parses")
        .application_name(&worker_name);
    let worker_conn = PgConnection::connect_with(&worker_opts)
        .await
        .expect("connect as hort-worker");

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT application_name FROM pg_stat_activity \
         WHERE application_name LIKE 'hort-%'",
    )
    .fetch_all(&pool)
    .await
    .expect("querying pg_stat_activity");
    let names: Vec<String> = rows.into_iter().map(|(n,)| n).collect();

    let expected_server_name =
        hort_config::pg_identity::pg_application_name(hort_config::pg_identity::SERVER_ROLE);
    assert!(
        names.contains(&expected_server_name),
        "expected {expected_server_name:?} in pg_stat_activity, got {names:?}"
    );
    assert!(
        names.contains(&worker_name),
        "expected {worker_name:?} in pg_stat_activity, got {names:?}"
    );

    drop(server_conn);
    drop(worker_conn);
    drop_temp_db(&admin, &db_name, pool).await;
}
