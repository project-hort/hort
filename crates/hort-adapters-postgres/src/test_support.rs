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
//! The throwaway database is intentionally **not** dropped: it is
//! uniquely named (`hort_test_<uuid>`), never collides, and CI runs
//! against a fresh `postgres` service per pipeline. Locally it is
//! harmless clutter, removed by recreating the dev DB.

use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Executor, PgConnection, PgPool};

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
    let db = format!("hort_test_{}", uuid::Uuid::new_v4().simple());

    // CREATE DATABASE cannot run in a transaction or target the
    // connected DB — use a maintenance connection to `postgres`.
    let mut admin = PgConnection::connect_with(&opts.clone().database("postgres"))
        .await
        .ok()?;
    admin
        .execute(format!("CREATE DATABASE \"{db}\"").as_str())
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
