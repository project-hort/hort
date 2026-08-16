//! `019_content_first_seen.sql` — the one-time seed of the content-level
//! age projection from the history the instance still holds.
//!
//! The table's write path is covered by
//! `hort_adapters_postgres::content_first_seen`'s own tests. What can
//! only be covered here is the migration's **data step**: it runs once,
//! against rows that exist *before* the file is applied, so a test that
//! starts from a fully-migrated database cannot observe it at all.
//!
//! Each test therefore drives the chain itself:
//!
//! 1. create an empty database (`isolated_unmigrated_db_from`),
//! 2. run every migration BELOW 019 through a version-filtered
//!    `Migrator` built from the same embedded set,
//! 3. seed `artifacts` rows — the pre-migration history,
//! 4. run the full set, which applies 019 and its seed,
//! 5. assert on `content_first_seen`.
//!
//! Requires `DATABASE_URL`; every test early-returns when it is unset so
//! the suite stays green without a database. Each carries
//! `#[serial(hort_pg_db)]` per the crate-wide parallel-safety contract.
//!
//! ```bash
//! DATABASE_URL=postgres://… \
//!   cargo test -p hort-adapters-postgres --test migration_019_content_first_seen_seed
//! ```

#![allow(clippy::expect_used)]

use chrono::{DateTime, Utc};
use serial_test::serial;
use sqlx::{migrate::Migrator, PgPool};
use std::env;
use uuid::Uuid;

/// The migration under test. Everything strictly below it is the
/// "before" state the seed reads.
const SEED_MIGRATION_VERSION: i64 = 19;

const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const HASH_B: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).expect("valid timestamp")
}

/// A fresh database migrated up to — but not including — 019.
///
/// Returns `None` when `DATABASE_URL` is unset or the target is
/// unreachable, matching the self-skip semantics of the rest of the
/// DB-gated suite.
async fn pool_before_the_seed() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_unmigrated_db_from(&url).await?;

    let full = sqlx::migrate!("../../migrations");
    assert!(
        full.migrations
            .iter()
            .any(|m| m.version == SEED_MIGRATION_VERSION),
        "no migration numbered {SEED_MIGRATION_VERSION} in the embedded set — if the \
         content_first_seen migration was renumbered, update SEED_MIGRATION_VERSION; \
         otherwise these tests would silently assert nothing"
    );

    // Same `Migration` values, same checksums — so the full run below
    // accepts what this run applied, and only 019 is left to apply.
    let before = Migrator::with_migrations(
        full.migrations
            .iter()
            .filter(|m| m.version < SEED_MIGRATION_VERSION)
            .cloned()
            .collect(),
    );
    before
        .run(&pool)
        .await
        .expect("migrations below the seed run cleanly");

    let table_exists: (bool,) =
        sqlx::query_as("SELECT to_regclass('public.content_first_seen') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .expect("probe for the projection table");
    assert!(
        !table_exists.0,
        "the projection table must not exist yet — the seed would then not be \
         what these tests observe"
    );

    Some(pool)
}

/// Apply the remaining migrations — i.e. 019 and its seed.
async fn apply_the_seed_migration(pool: &PgPool) {
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .expect("the full migration chain runs cleanly over the seeded history");
}

/// Seed a repository row and return its id.
async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-mig019-{}", id.simple());
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $2,
               'generic'::repository_format,
               'hosted'::repository_type,
               'filesystem', $3,
               'local_only'::replication_priority
           )"#,
    )
    .bind(id)
    .bind(&key)
    .bind(format!("/tmp/{key}"))
    .execute(pool)
    .await
    .expect("seed repository row");
    id
}

/// Seed an `artifacts` row carrying `checksum` and `created_at`.
///
/// `checksum` is deliberately a `&str` rather than a `ContentHash`: some
/// tests need to store a value the domain type could never produce.
async fn seed_artifact(
    pool: &PgPool,
    repo: Uuid,
    checksum: &str,
    created_at: DateTime<Utc>,
    is_deleted: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key,
               created_at, is_deleted
           ) VALUES (
               $1, $2, 'a', 'a', '1.0.0', $3,
               0, $4, 'application/octet-stream', $3,
               $5, $6
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(format!("artifacts/a-{}", id.simple()))
    .bind(checksum)
    .bind(created_at)
    .bind(is_deleted)
    .execute(pool)
    .await
    .expect("seed artifact row");
    id
}

/// Every seeded record, ordered by hash.
async fn projection_rows(pool: &PgPool) -> Vec<(String, DateTime<Utc>)> {
    sqlx::query_as(
        "SELECT content_hash, first_seen_at FROM public.content_first_seen \
         ORDER BY content_hash",
    )
    .fetch_all(pool)
    .await
    .expect("read the projection")
}

/// The acceptance criterion: one hash held by two repositories at
/// different times yields ONE record, at the earlier instant.
///
/// The later row is seeded first so a seed that simply took the last
/// value it saw — or the first — would fail rather than pass by luck.
#[tokio::test]
#[serial(hort_pg_db)]
async fn seed_recovers_the_earliest_created_at_across_repositories() {
    let Some(pool) = pool_before_the_seed().await else {
        return;
    };

    let repo_late = seed_repo(&pool).await;
    let repo_early = seed_repo(&pool).await;
    seed_artifact(&pool, repo_late, HASH_A, at(9_000), false).await;
    seed_artifact(&pool, repo_early, HASH_A, at(1_000), false).await;

    apply_the_seed_migration(&pool).await;

    let rows = projection_rows(&pool).await;
    assert_eq!(
        rows,
        vec![(HASH_A.to_string(), at(1_000))],
        "one record per content hash, holding the earliest observation \
         still evidenced by a live row"
    );
}

/// A hash whose only remaining evidence is a soft-deleted row is still
/// recovered, at that row's instant. The observation happened; the soft
/// delete does not unmake it, and skipping such rows could only move the
/// recovered instant later.
#[tokio::test]
#[serial(hort_pg_db)]
async fn seed_includes_soft_deleted_rows() {
    let Some(pool) = pool_before_the_seed().await else {
        return;
    };

    let repo = seed_repo(&pool).await;
    seed_artifact(&pool, repo, HASH_A, at(1_000), true).await;
    seed_artifact(&pool, repo, HASH_B, at(2_000), false).await;

    apply_the_seed_migration(&pool).await;

    // `projection_rows` orders by hash: HASH_B ("b94d…") sorts before
    // HASH_A ("e3b0…").
    assert_eq!(
        projection_rows(&pool).await,
        vec![
            (HASH_B.to_string(), at(2_000)),
            (HASH_A.to_string(), at(1_000)),
        ],
        "a soft-deleted row is still evidence that hort held those bytes"
    );
}

/// A stored checksum that could not satisfy the projection's shape CHECK
/// is SKIPPED — the migration still applies, and every canonical row
/// around it is still recovered.
///
/// `artifacts.checksum_sha256` carries no CHECK of its own, and 003 is a
/// squashed baseline over a prototype history that did not guarantee the
/// canonical form. Letting such a row abort the statement would mean the
/// deployment does not boot.
#[tokio::test]
#[serial(hort_pg_db)]
async fn seed_skips_a_non_canonical_checksum_instead_of_aborting() {
    let Some(pool) = pool_before_the_seed().await else {
        return;
    };

    let repo = seed_repo(&pool).await;
    // Uppercase: 64 characters, but not the canonical form.
    seed_artifact(&pool, repo, &HASH_A.to_ascii_uppercase(), at(1_000), false).await;
    // Short: `character(64)` blank-pads it, and the pad is trimmed by
    // the cast to `text`, so it reaches the CHECK too short.
    seed_artifact(&pool, repo, "deadbeef", at(2_000), false).await;
    // Canonical, and must survive its neighbours.
    seed_artifact(&pool, repo, HASH_B, at(3_000), false).await;

    apply_the_seed_migration(&pool).await;

    assert_eq!(
        projection_rows(&pool).await,
        vec![(HASH_B.to_string(), at(3_000))],
        "non-canonical rows are skipped; the migration applies regardless"
    );
}

/// A fresh install has nothing to recover: the seed selects no rows and
/// leaves the table empty rather than failing.
#[tokio::test]
#[serial(hort_pg_db)]
async fn seed_is_a_no_op_when_there_is_no_history() {
    let Some(pool) = pool_before_the_seed().await else {
        return;
    };

    apply_the_seed_migration(&pool).await;

    assert!(
        projection_rows(&pool).await.is_empty(),
        "nothing to seed on a fresh install"
    );
}
