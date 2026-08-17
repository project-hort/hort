//! Test-only support: **per-test database isolation**.
//!
//! `#[doc(hidden)]` — not part of the public API; compiled always so
//! that `hort-adapters-postgres`'s own `#[cfg(test)]` modules, its
//! `tests/` integration binaries, and the `hort-server` / `hort-worker`
//! integration tests can all share one isolation helper without a
//! feature-flag dance.
//!
//! ## Why
//!
//! The DB-backed test suites historically connected to ONE shared
//! database and each ran `sqlx::migrate!().run()` against it. Under
//! `cargo test --tests` cargo runs many test binaries in parallel, so
//! they raced and corrupted each other's schema/data (concurrent
//! migrate, `DROP TABLE … CASCADE` collateral, before/after deltas on
//! global streams, …). [`isolated_db_from`] gives every caller its own
//! freshly-created database, so cross-test/cross-binary interference is
//! structurally impossible. The caller still runs its own
//! `sqlx::migrate!().run()` on the returned pool (kept at the call site
//! so the embedded-migration set stays crate-local; the workspace
//! `build.rs` files make that embed track `migrations`).
//!
//! ## Cleanup — bounded, not unbounded (issue #37)
//!
//! A throwaway database is still not dropped at the end of its own
//! test (there is no teardown hook — [`isolated_db_from`] hands back a
//! bare `PgPool`). Instead each test **process** sweeps stale ones
//! once, before creating its own.
//!
//! This reverses an earlier decision. That comment read: *"intentionally
//! not dropped … locally it is harmless clutter, removed by recreating
//! the dev DB."* Both premises expired once the dev environment became
//! fully automated: nobody recreates the dev DB by hand, so the
//! databases accumulated monotonically — **1,091 of them, 11 GB**, at
//! which point every unclean postgres restart replayed a ~2.5-minute
//! recovery (64k files fsynced, 715 MB of WAL) and every connection
//! attempt inside that window failed with `57P03` / `PoolTimedOut`.
//! That was the whole of issue #37's "flakiness".
//!
//! The sweep is safe by construction, not by luck:
//!
//! - the database name carries its creation time
//!   (`hort_test_<unix_secs>_<uuid>`), and only entries older than
//!   [`STALE_AFTER_SECS`] are considered — so a database another
//!   process created moments ago is never a candidate, even mid-sweep;
//! - candidates with any live connection in `pg_stat_activity` are
//!   skipped, so a long-running concurrent test is doubly protected;
//! - every step is best-effort: any error is ignored and the caller
//!   proceeds to create its own database. Cleanup must never be the
//!   reason a test fails.
//!
//! This bounds accumulation to roughly one run's worth. It does not
//! *prevent* a leak — a drop-on-teardown guard would, at the cost of a
//! guard type threaded through 22 test files and a database drop issued
//! from a synchronous `Drop`. Deliberately not done; revisit only if
//! the between-sweep accumulation ever bites.

use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Executor, PgConnection, PgPool};

/// Age below which a stray `hort_test_*` database is left alone. Well
/// above any single test's lifetime, so a concurrently-running test is
/// never a sweep candidate.
const STALE_AFTER_SECS: u64 = 3600;

/// Ensures the stale-database sweep runs at most once per process.
static SWEPT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Drop `hort_test_*` databases older than [`STALE_AFTER_SECS`] that
/// have no live connections. Best-effort: every failure is ignored.
///
/// Runs at most once per process (first [`isolated_db_from`] call).
/// Takes the maintenance connection already opened for `CREATE
/// DATABASE`, so it costs no extra connection.
async fn sweep_stale_databases(admin: &mut PgConnection) {
    use std::sync::atomic::Ordering;
    if SWEPT.swap(true, Ordering::SeqCst) {
        return;
    }

    let cutoff = now_unix_secs().saturating_sub(STALE_AFTER_SECS);

    // `split_part(datname, '_', 3)` is the epoch segment of
    // `hort_test_<epoch>_<uuid>`. Databases predating the timestamped
    // naming have a non-numeric segment there; `~ '^[0-9]+$'` excludes
    // them from the age test, and the second arm sweeps them on the
    // connection check alone (they are, by definition, older).
    let sql = format!(
        "SELECT d.datname FROM pg_database d \
         LEFT JOIN (SELECT datname, count(*) AS cnt FROM pg_stat_activity GROUP BY datname) a \
           ON a.datname = d.datname \
         WHERE d.datname LIKE 'hort\\_test\\_%' \
           AND COALESCE(a.cnt, 0) = 0 \
           AND (CASE WHEN split_part(d.datname, '_', 3) ~ '^[0-9]+$' \
                     THEN split_part(d.datname, '_', 3)::bigint < {cutoff} \
                     ELSE true END)"
    );

    let Ok(rows) = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
        .fetch_all(&mut *admin)
        .await
    else {
        return;
    };
    for name in rows {
        // DROP DATABASE cannot run in a transaction; a concurrent
        // connection arriving between the query and here makes this
        // fail, which is exactly the outcome we want — skip it.
        let _ = admin
            .execute(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS \"{name}\""
            )))
            .await;
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Create a uniquely-named database (derived from `base_url`: same
/// host/user/password, fresh dbname) and return a pool connected to it.
/// The DB is **empty** — the caller runs its own
/// `sqlx::migrate!().run()` on the returned pool.
///
/// Returns `None` on any failure (mirrors the prior
/// `PgPool::connect(&url).await.ok()?` semantics so the suite stays
/// green when `DATABASE_URL` is unset / the DB is unreachable).
pub async fn isolated_db_from(base_url: &str) -> Option<PgPool> {
    let opts: PgConnectOptions = base_url.parse().ok()?;
    // The epoch segment is load-bearing: `sweep_stale_databases` reads
    // it to age-gate candidates. Keep the `hort_test_<epoch>_<uuid>`
    // shape if you rename this.
    let db = format!(
        "hort_test_{}_{}",
        now_unix_secs(),
        uuid::Uuid::new_v4().simple()
    );

    // CREATE DATABASE cannot run in a transaction or target the
    // connected DB — use a maintenance connection to `postgres`.
    let mut admin = PgConnection::connect_with(&opts.clone().database("postgres"))
        .await
        .ok()?;

    // Once per process, on the connection we already hold.
    sweep_stale_databases(&mut admin).await;

    admin
        .execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{db}\"")))
        .await
        .ok()?;
    let _ = admin.close().await;

    let pool = PgPool::connect_with(opts.database(&db)).await.ok()?;

    // Migrate here, with a bounded retry. Per-test DB isolation means
    // ~80+ test binaries each `CREATE DATABASE` + run the full
    // (DDL-heavy, cluster-global `CREATE ROLE`) migration set
    // concurrently against one Postgres; that thundering herd
    // intermittently makes a single migration run fail on shared-catalog
    // lock contention. A few spaced retries absorb the transient
    // contention. On persistent failure the pool is still returned: the
    // call site's own `sqlx::migrate!().run()` then runs (a no-op once
    // migrated; otherwise it surfaces the real error via its `.expect`,
    // so a genuine migration bug is never masked into a silent skip).
    for attempt in 0..4u32 {
        match sqlx::migrate!("../../migrations").run(&pool).await {
            Ok(()) => break,
            Err(_) if attempt < 3 => {
                tokio::time::sleep(std::time::Duration::from_millis(
                    150 * u64::from(attempt + 1),
                ))
                .await;
            }
            Err(_) => break,
        }
    }
    Some(pool)
}

/// Connect to the shared `DATABASE_URL` target — not a per-test isolated
/// database — and ensure it is migrated before handing back the pool.
///
/// For tests that deliberately exercise shared-DB behavior under the
/// `#[serial(hort_pg_db)]` contract (isolation would defeat the point of
/// the test). Every caller against the shared target must migrate through
/// here: `#[serial(hort_pg_db)]` name-orders tests within a binary, but
/// gives no ordering guarantee *across* the several modules that share
/// this database, so no test may assume an earlier-sorting module already
/// migrated it.
///
/// Returns `None` when `DATABASE_URL` is unset or the target is
/// unreachable (mirrors [`isolated_db_from`]'s self-skip semantics). A
/// migration that fails after retries is a real bug, not a skip
/// condition, and panics rather than handing back an unmigrated pool.
pub async fn shared_migrated_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPool::connect(&url).await.ok()?;

    // Bounded retry: the shared target is a migration race between every
    // test binary that reaches this helper concurrently, the same
    // thundering-herd contention `isolated_db_from` absorbs above.
    let mut last_err = None;
    for attempt in 0..4u32 {
        match sqlx::migrate!("../../migrations").run(&pool).await {
            Ok(()) => return Some(pool),
            Err(err) => {
                last_err = Some(err);
                if attempt < 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        150 * u64::from(attempt + 1),
                    ))
                    .await;
                }
            }
        }
    }
    panic!("migrations failed against the shared DATABASE_URL target after retries: {last_err:?}");
}
