//! `PgRepoSecurityScoreRepository` integration tests.
//!
//! Exercises the `repo_security_scores` projection (migration 009 §3.6)
//! end-to-end against a real Postgres. DATABASE_URL-gated; tests early-
//! return when unset so dev environments without a database keep the
//! suite green. Mirrors the convention in
//! `migration_009_jobs_and_findings.rs`.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test repo_security_score_repository
//! ```

#![allow(clippy::expect_used)]

use std::env;

use chrono::{SubsecRound, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::repo_security_score_repository::{
    apply_delta_in_tx, PgRepoSecurityScoreRepository,
};
use hort_domain::ports::repo_security_score_repository::{
    RepoSecurityScore, RepoSecurityScoreRepository, ScoreDelta,
};

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

/// Seed a `repositories` row with random-but-valid identifiers so the
/// FK on `repo_security_scores.repository_id → repositories(id)`
/// (migration 009, M3) holds. Mirrors the helper in
/// `migration_009_jobs_and_findings.rs::seed_repo`.
async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-secscore-{}", id.simple());
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $3,
               'pypi'::repository_format,
               'hosted'::repository_type,
               'filesystem', $4,
               'local_only'::replication_priority
           )"#,
    )
    .bind(id)
    .bind(&key)
    .bind(&key)
    .bind(format!("/tmp/{key}"))
    .execute(pool)
    .await
    .expect("seed_repo");
    id
}

/// Cleanup helper — drop the seeded repository, cascading through
/// `repo_security_scores` (M3 ON DELETE CASCADE). Called at the end of
/// each test that seeded a row.
async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

#[tokio::test]
async fn upsert_then_find_round_trips() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let now = Utc::now();
    let row = RepoSecurityScore {
        repository_id: repo_id,
        quarantined_count: 1,
        rejected_count: 2,
        released_count: 3,
        critical_count: 4,
        high_count: 5,
        medium_count: 6,
        low_count: 7,
        last_scan_at: Some(now),
        updated_at: now,
    };

    let repo = PgRepoSecurityScoreRepository::new(pool.clone());
    repo.upsert(&row).await.expect("upsert");
    let found = repo.find(repo_id).await.expect("find").expect("row exists");
    assert_eq!(found.repository_id, repo_id);
    assert_eq!(found.quarantined_count, 1);
    assert_eq!(found.rejected_count, 2);
    assert_eq!(found.released_count, 3);
    assert_eq!(found.critical_count, 4);
    assert_eq!(found.high_count, 5);
    assert_eq!(found.medium_count, 6);
    assert_eq!(found.low_count, 7);

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
async fn find_missing_returns_none() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = Uuid::new_v4();
    let repo = PgRepoSecurityScoreRepository::new(pool.clone());
    let res = repo.find(repo_id).await.expect("find");
    assert!(res.is_none());
}

#[tokio::test]
async fn upsert_replaces_existing_row() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    // Postgres `timestamptz` stores microsecond precision; `Utc::now()`
    // returns nanoseconds. Truncate before storing so the equality
    // assertion below survives the storage round-trip.
    let now = Utc::now().trunc_subsecs(6);
    let repo = PgRepoSecurityScoreRepository::new(pool.clone());

    let first = RepoSecurityScore {
        repository_id: repo_id,
        quarantined_count: 5,
        rejected_count: 0,
        released_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        last_scan_at: None,
        updated_at: now,
    };
    repo.upsert(&first).await.expect("first upsert");

    let second = RepoSecurityScore {
        repository_id: repo_id,
        quarantined_count: 0,
        rejected_count: 7,
        released_count: 0,
        critical_count: 1,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        last_scan_at: Some(now),
        updated_at: now,
    };
    repo.upsert(&second).await.expect("second upsert");

    let found = repo.find(repo_id).await.expect("find").expect("row");
    assert_eq!(found.quarantined_count, 0);
    assert_eq!(found.rejected_count, 7);
    assert_eq!(found.critical_count, 1);
    assert_eq!(found.last_scan_at, Some(now));

    cleanup(&pool, repo_id).await;
}

/// `apply_delta_in_tx` against a missing row inserts the row from a
/// zero baseline.
#[tokio::test]
async fn apply_delta_in_tx_inserts_missing_row() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let mut tx = pool.begin().await.expect("begin tx");
    let delta = ScoreDelta {
        quarantined_delta: 1,
        critical_delta: 2,
        high_delta: 3,
        ..ScoreDelta::default()
    };
    apply_delta_in_tx(&mut tx, repo_id, &delta)
        .await
        .expect("apply_delta");
    tx.commit().await.expect("commit");

    let repo = PgRepoSecurityScoreRepository::new(pool.clone());
    let found = repo.find(repo_id).await.expect("find").expect("row");
    assert_eq!(found.quarantined_count, 1);
    assert_eq!(found.critical_count, 2);
    assert_eq!(found.high_count, 3);
    assert_eq!(found.released_count, 0);

    cleanup(&pool, repo_id).await;
}

/// `apply_delta_in_tx` against an existing row adds the delta and
/// clamps underflow at zero (`repo_security_scores` projection invariant).
#[tokio::test]
async fn apply_delta_in_tx_clamps_underflow_at_zero() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;

    // Seed: quarantined=0, rejected=5.
    let now = Utc::now();
    let repo = PgRepoSecurityScoreRepository::new(pool.clone());
    repo.upsert(&RepoSecurityScore {
        repository_id: repo_id,
        quarantined_count: 0,
        rejected_count: 5,
        released_count: 1,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        last_scan_at: None,
        updated_at: now,
    })
    .await
    .expect("seed");

    // Subtract 10 from already-zero quarantined — must clamp at zero.
    let mut tx = pool.begin().await.expect("begin tx");
    let delta = ScoreDelta {
        quarantined_delta: -10,
        rejected_delta: -1,
        released_delta: 1,
        ..ScoreDelta::default()
    };
    apply_delta_in_tx(&mut tx, repo_id, &delta)
        .await
        .expect("apply_delta");
    tx.commit().await.expect("commit");

    let found = repo.find(repo_id).await.expect("find").expect("row");
    assert_eq!(found.quarantined_count, 0, "clamped at zero");
    assert_eq!(found.rejected_count, 4);
    assert_eq!(found.released_count, 2);

    cleanup(&pool, repo_id).await;
}

/// A noop delta is a true noop — the SQL is skipped entirely.
#[tokio::test]
async fn apply_delta_in_tx_noop_does_not_create_row() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("begin tx");
    apply_delta_in_tx(&mut tx, repo_id, &ScoreDelta::default())
        .await
        .expect("noop apply");
    tx.commit().await.expect("commit");

    let repo = PgRepoSecurityScoreRepository::new(pool.clone());
    assert!(
        repo.find(repo_id).await.expect("find").is_none(),
        "noop delta must not create a row"
    );
}

/// `last_scan_at` propagates from the delta when set, and is preserved
/// otherwise (the COALESCE in the upsert).
#[tokio::test]
async fn apply_delta_in_tx_last_scan_at_set_then_preserved() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    // See note on `upsert_replaces_existing_row`: PG truncates to micros.
    let scan_time = Utc::now().trunc_subsecs(6);
    let repo = PgRepoSecurityScoreRepository::new(pool.clone());

    // First call sets last_scan_at.
    let mut tx = pool.begin().await.expect("begin tx");
    apply_delta_in_tx(
        &mut tx,
        repo_id,
        &ScoreDelta {
            critical_delta: 1,
            last_scan_at: Some(scan_time),
            ..ScoreDelta::default()
        },
    )
    .await
    .expect("apply 1");
    tx.commit().await.expect("commit 1");

    // Second call (status-only delta, no last_scan_at) — must
    // preserve the previously-set value.
    let mut tx = pool.begin().await.expect("begin tx");
    apply_delta_in_tx(
        &mut tx,
        repo_id,
        &ScoreDelta {
            quarantined_delta: 1,
            ..ScoreDelta::default()
        },
    )
    .await
    .expect("apply 2");
    tx.commit().await.expect("commit 2");

    let found = repo.find(repo_id).await.expect("find").expect("row");
    assert_eq!(found.last_scan_at, Some(scan_time));
    assert_eq!(found.critical_count, 1);
    assert_eq!(found.quarantined_count, 1);

    cleanup(&pool, repo_id).await;
}

/// Two sequential applies in independent transactions are consistent
/// (post-commit reads see the cumulative state).
#[tokio::test]
async fn sequential_applies_are_consistent() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let repo = PgRepoSecurityScoreRepository::new(pool.clone());

    for _ in 0..3 {
        let mut tx = pool.begin().await.expect("begin tx");
        apply_delta_in_tx(
            &mut tx,
            repo_id,
            &ScoreDelta {
                quarantined_delta: 1,
                ..ScoreDelta::default()
            },
        )
        .await
        .expect("apply");
        tx.commit().await.expect("commit");
    }

    let found = repo.find(repo_id).await.expect("find").expect("row");
    assert_eq!(found.quarantined_count, 3);

    cleanup(&pool, repo_id).await;
}
