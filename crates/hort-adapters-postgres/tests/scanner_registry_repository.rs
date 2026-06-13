//! `PgScannerRegistryRepository` integration tests
//! against the `scanner_registry` table from migration 009.
//!
//! `DATABASE_URL`-gated per the project convention. When unset, every
//! test early-returns `Ok` so dev environments without a database keep
//! the suite green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test scanner_registry_repository
//! ```
//!
//! Coverage:
//!
//! - `upsert_self_inserts_new_row_with_now_timestamps`
//! - `upsert_self_preserves_registered_at_on_conflict`
//! - `upsert_self_rewrites_backends_on_conflict`
//! - `refresh_heartbeat_updates_last_heartbeat`
//! - `list_live_filters_by_liveness_window`

#![allow(clippy::expect_used)]

use std::env;
use std::sync::OnceLock;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use uuid::Uuid;

use hort_adapters_postgres::scanner_registry_repository::PgScannerRegistryRepository;
use hort_domain::ports::scanner_registry_repository::ScannerRegistryRepository;

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

/// Per-binary serialization gate. Mirrors the `jobs_repository.rs`
/// rationale — the table is shared across cargo's intra-binary
/// parallelism and rows would otherwise interfere across tests.
fn serial_lock() -> &'static AsyncMutex<()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(()))
}

async fn lock_serial() -> AsyncMutexGuard<'static, ()> {
    serial_lock().lock().await
}

/// Generate a unique worker_id per test so concurrent test binaries
/// don't collide on the primary key.
fn fresh_worker_id() -> String {
    format!("test-worker-{}", Uuid::new_v4())
}

/// Fetch the row directly so the assertion isn't read through the port
/// itself (would mask the adapter's UPDATE / INSERT column choices).
async fn fetch_row(
    pool: &PgPool,
    worker_id: &str,
) -> Option<(Vec<String>, DateTime<Utc>, DateTime<Utc>)> {
    let row: Option<(Vec<String>, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT backends, registered_at, last_heartbeat \
           FROM public.scanner_registry \
          WHERE worker_id = $1",
    )
    .bind(worker_id)
    .fetch_optional(pool)
    .await
    .expect("fetch scanner_registry row");
    row
}

#[tokio::test]
async fn upsert_self_inserts_new_row_with_now_timestamps() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgScannerRegistryRepository::new(pool.clone());

    let worker_id = fresh_worker_id();
    repo.upsert_self(&worker_id, vec!["trivy".into(), "osv".into()])
        .await
        .expect("upsert_self");

    let row = fetch_row(&pool, &worker_id)
        .await
        .expect("row exists after upsert");
    let (backends, registered_at, last_heartbeat) = row;
    assert_eq!(backends, vec!["trivy".to_string(), "osv".to_string()]);
    // registered_at == last_heartbeat on first insert (within drift —
    // both are `now()` from the same statement).
    let drift = (last_heartbeat - registered_at).num_seconds().abs();
    assert!(
        drift < 2,
        "registered_at vs last_heartbeat drifted {drift}s"
    );
}

#[tokio::test]
async fn upsert_self_preserves_registered_at_on_conflict() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgScannerRegistryRepository::new(pool.clone());

    let worker_id = fresh_worker_id();
    repo.upsert_self(&worker_id, vec!["trivy".into()])
        .await
        .expect("first upsert_self");
    let (_, first_registered_at, _) = fetch_row(&pool, &worker_id).await.expect("first row");

    // Sleep briefly so a fresh `now()` would be observably different
    // if the adapter rewrote `registered_at`.
    tokio::time::sleep(Duration::from_millis(50)).await;

    repo.upsert_self(&worker_id, vec!["trivy".into()])
        .await
        .expect("second upsert_self");
    let (_, second_registered_at, _) = fetch_row(&pool, &worker_id).await.expect("second row");

    assert_eq!(
        first_registered_at, second_registered_at,
        "registered_at must be pinned across upserts"
    );
}

#[tokio::test]
async fn upsert_self_rewrites_backends_on_conflict() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgScannerRegistryRepository::new(pool.clone());

    let worker_id = fresh_worker_id();
    repo.upsert_self(&worker_id, vec!["trivy".into()])
        .await
        .expect("first upsert_self");

    repo.upsert_self(&worker_id, vec!["trivy".into(), "osv".into()])
        .await
        .expect("second upsert_self");

    let (backends, _, _) = fetch_row(&pool, &worker_id).await.expect("row");
    assert_eq!(
        backends,
        vec!["trivy".to_string(), "osv".to_string()],
        "second upsert must overwrite backends"
    );
}

#[tokio::test]
async fn refresh_heartbeat_updates_last_heartbeat() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgScannerRegistryRepository::new(pool.clone());

    let worker_id = fresh_worker_id();
    repo.upsert_self(&worker_id, vec!["trivy".into()])
        .await
        .expect("seed");
    let (_, _, before) = fetch_row(&pool, &worker_id).await.expect("seed row");

    tokio::time::sleep(Duration::from_millis(50)).await;
    repo.refresh_heartbeat(&worker_id)
        .await
        .expect("refresh_heartbeat");

    let (_, _, after) = fetch_row(&pool, &worker_id).await.expect("post-tick row");
    assert!(
        after > before,
        "refresh_heartbeat must move last_heartbeat forward (before={before}, after={after})"
    );
}

#[tokio::test]
async fn list_live_filters_by_liveness_window() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo = PgScannerRegistryRepository::new(pool.clone());

    // Seed one row with a fresh heartbeat (live) and one with a stale
    // heartbeat (dead). We tamper with `last_heartbeat` directly so we
    // don't have to actually sleep 5+ minutes in the test.
    let live_worker = fresh_worker_id();
    let dead_worker = fresh_worker_id();
    repo.upsert_self(&live_worker, vec!["trivy".into()])
        .await
        .expect("seed live");
    repo.upsert_self(&dead_worker, vec!["osv".into()])
        .await
        .expect("seed dead");

    sqlx::query("UPDATE public.scanner_registry SET last_heartbeat = now() - interval '1 hour' WHERE worker_id = $1")
        .bind(&dead_worker)
        .execute(&pool)
        .await
        .expect("backdate dead worker");

    let live = repo
        .list_live(Duration::from_secs(300))
        .await
        .expect("list_live");
    let live_ids: Vec<&str> = live.iter().map(|e| e.worker_id.as_str()).collect();

    assert!(
        live_ids.contains(&live_worker.as_str()),
        "live worker must appear in list_live (got {live_ids:?})"
    );
    assert!(
        !live_ids.contains(&dead_worker.as_str()),
        "dead worker must NOT appear in list_live (got {live_ids:?})"
    );
}
