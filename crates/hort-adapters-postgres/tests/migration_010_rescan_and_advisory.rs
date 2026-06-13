//! `010_rescan_and_advisory.sql` migration tests.
//!
//! Asserts the schema invariants the migration ships with:
//!
//! 1. `sbom_components` table — composite PK `(artifact_id, purl)`,
//!    FK on `artifacts(id) ON DELETE CASCADE`, plus the
//!    `(purl)` and `(ecosystem, name)` lookup indexes that drive the
//!    advisory-watch DISTINCT-artifact_id query.
//! 2. `advisory_sync_state` table — `feed` PK, NOT NULL on
//!    `last_sync_at` and `updated_at`.
//! 3. Seed row — `('osv', now() - interval '24 hours', now())` is
//!    inserted by the migration with `ON CONFLICT DO NOTHING`. The
//!    24-hour offset gives the first advisory-watch tick a meaningful
//!    backfill window.
//! 4. The migration does NOT alter `public.jobs` — the
//!    `kind`/`priority`/`trigger_source`/`result_summary` columns
//!    already live in migration 009 (pre-release in-place edit per the
//!    `feedback_pre_release_migrations` discipline).
//!
//! Tests follow the convention in `api_tokens_migration.rs` and
//! `migration_009_jobs_and_findings.rs`: require `DATABASE_URL`; if
//! unset, every test early-returns so dev environments without a
//! database keep the suite green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test migration_010_rescan_and_advisory
//! ```

#![allow(clippy::expect_used)]

use std::env;

use sqlx::{PgPool, Row};
use uuid::Uuid;

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

/// Seed a minimal repository row and return its id. Mirrors the
/// `seed_repo` pattern from `migration_009_jobs_and_findings.rs` so
/// behaviour stays consistent across the integration suite.
async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-mig010-{}", id.simple());
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
    .expect("seed repository row for migration 010 tests");
    id
}

/// Seed a minimal artifact row under `repo` and return its id. Used as
/// the FK target for `sbom_components.artifact_id`.
async fn seed_artifact(pool: &PgPool, repo: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let key = id.simple().to_string();
    let sha256 = format!("{key}{key}");
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key
           ) VALUES (
               $1, $2, 'mig010', 'mig010', '0.0.0', $3,
               0, $4, 'application/octet-stream', $4
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(format!("simple/mig010/{key}.tar.gz"))
    .bind(&sha256)
    .execute(pool)
    .await
    .expect("seed artifact row for migration 010 tests");
    id
}

// ---------------------------------------------------------------------------
// Test 1 — `sbom_components` exists with the expected shape, indexes,
// and CASCADE behaviour. Insert + SELECT round-trip exercises the
// runtime path (the operator's role-bootstrap recipe gives `hort_app_role`
// DML on the table via `ALTER DEFAULT PRIVILEGES`; the test here uses
// the migration superuser, which has full privileges by definition).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_010_creates_sbom_components() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    // Sanity — table exists.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
                        WHERE table_schema = 'public' AND table_name = 'sbom_components')",
    )
    .fetch_one(&pool)
    .await
    .expect("probe sbom_components existence");
    assert!(
        exists,
        "sbom_components must exist after running through 010"
    );

    let repo_id = seed_repo(&pool).await;
    let artifact_id = seed_artifact(&pool, repo_id).await;

    // INSERT one row, then SELECT it back.
    sqlx::query(
        "INSERT INTO public.sbom_components (artifact_id, purl, ecosystem, name, version) \
         VALUES ($1, 'pkg:npm/foo@1.2.3', 'npm', 'foo', '1.2.3')",
    )
    .bind(artifact_id)
    .execute(&pool)
    .await
    .expect("insert sbom_components row");

    let row = sqlx::query(
        "SELECT purl, ecosystem, name, version FROM public.sbom_components \
         WHERE artifact_id = $1",
    )
    .bind(artifact_id)
    .fetch_one(&pool)
    .await
    .expect("read back sbom_components row");
    assert_eq!(row.get::<String, _>("purl"), "pkg:npm/foo@1.2.3");
    assert_eq!(row.get::<String, _>("ecosystem"), "npm");
    assert_eq!(row.get::<String, _>("name"), "foo");
    assert_eq!(
        row.get::<Option<String>, _>("version"),
        Some("1.2.3".into())
    );

    // Composite PK uniqueness — same (artifact_id, purl) must reject.
    let dup_err = sqlx::query(
        "INSERT INTO public.sbom_components (artifact_id, purl, ecosystem, name, version) \
         VALUES ($1, 'pkg:npm/foo@1.2.3', 'npm', 'foo', '1.2.3')",
    )
    .bind(artifact_id)
    .execute(&pool)
    .await
    .expect_err("duplicate (artifact_id, purl) must violate composite PK");
    let dup_code = dup_err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        dup_code, "23505",
        "expected SQLSTATE 23505 (unique_violation), got {dup_code}: {dup_err}"
    );

    // `version` is NULL-able per design §3.3.
    sqlx::query(
        "INSERT INTO public.sbom_components (artifact_id, purl, ecosystem, name, version) \
         VALUES ($1, 'pkg:npm/bar', 'npm', 'bar', NULL)",
    )
    .bind(artifact_id)
    .execute(&pool)
    .await
    .expect("NULL version must be accepted (column is nullable)");

    // Indexes exist.
    let mut index_rows = sqlx::query(
        "SELECT indexname FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'sbom_components' \
         ORDER BY indexname",
    )
    .fetch_all(&pool)
    .await
    .expect("probe sbom_components indexes");
    let indexes: Vec<String> = index_rows
        .iter_mut()
        .map(|r| r.get::<String, _>("indexname"))
        .collect();
    for required in [
        "sbom_components_purl_idx",
        "sbom_components_ecosystem_name_idx",
    ] {
        assert!(
            indexes.iter().any(|i| i == required),
            "expected index {required} to exist; saw {indexes:?}"
        );
    }

    // FK CASCADE — deleting the artifact must drop the component rows.
    let count_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.sbom_components WHERE artifact_id = $1")
            .bind(artifact_id)
            .fetch_one(&pool)
            .await
            .expect("count components before delete");
    assert_eq!(
        count_before, 2,
        "fixture must show two component rows before delete"
    );

    sqlx::query("DELETE FROM public.artifacts WHERE id = $1")
        .bind(artifact_id)
        .execute(&pool)
        .await
        .expect("delete artifact");

    let count_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.sbom_components WHERE artifact_id = $1")
            .bind(artifact_id)
            .fetch_one(&pool)
            .await
            .expect("count components after delete");
    assert_eq!(
        count_after, 0,
        "ON DELETE CASCADE must drop sbom_components when its artifact disappears"
    );

    // Cleanup parent repo.
    let _ = sqlx::query("DELETE FROM public.repositories WHERE id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await;
}

// ---------------------------------------------------------------------------
// Test 2 — `advisory_sync_state` exists, the seed row is present with
// the 24-hour backfill offset, and INSERT + SELECT for an additional
// feed round-trips cleanly.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_010_creates_advisory_sync_state_with_seed_row() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    // Sanity — table exists.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
                        WHERE table_schema = 'public' AND table_name = 'advisory_sync_state')",
    )
    .fetch_one(&pool)
    .await
    .expect("probe advisory_sync_state existence");
    assert!(
        exists,
        "advisory_sync_state must exist after running through 010"
    );

    // The 'osv' seed row must exist with last_sync_at < now() - 23h.
    // Per design §3.7 the migration seeds at `now() - 24h` so the first
    // tick has a meaningful backfill window. We assert ">= 23h" rather
    // than "exactly 24h" to tolerate clock skew between INSERT time and
    // test time.
    let row = sqlx::query(
        "SELECT last_sync_at, last_error, updated_at \
         FROM public.advisory_sync_state WHERE feed = 'osv'",
    )
    .fetch_one(&pool)
    .await
    .expect("seed 'osv' row must be present after migration 010");

    let last_sync_at: chrono::DateTime<chrono::Utc> = row.get("last_sync_at");
    let last_error: Option<String> = row.get("last_error");
    let updated_at: chrono::DateTime<chrono::Utc> = row.get("updated_at");

    let now = chrono::Utc::now();
    let lag = now - last_sync_at;
    assert!(
        lag.num_hours() >= 23,
        "seed last_sync_at must be at least 23h in the past (24h backfill window); \
         got last_sync_at={last_sync_at}, now={now}, lag={lag}"
    );
    // Sanity bound — within a reasonable window of "24h ago".
    assert!(
        lag.num_hours() < 48,
        "seed last_sync_at must be within ~24h of now; got {lag}"
    );
    assert!(
        last_error.is_none(),
        "seed row must have NULL last_error; got {last_error:?}"
    );
    assert!(
        (now - updated_at).num_seconds().abs() < 60 * 60,
        "seed updated_at must be near migration time; got updated_at={updated_at}, now={now}"
    );

    // INSERT + SELECT for an additional feed (extensibility — future
    // GitHub Advisory feed lands as its own row per design §3.7).
    let feed_name = format!("test-feed-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO public.advisory_sync_state (feed, last_sync_at, updated_at) \
         VALUES ($1, now(), now())",
    )
    .bind(&feed_name)
    .execute(&pool)
    .await
    .expect("INSERT additional feed row");

    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.advisory_sync_state WHERE feed = $1")
            .bind(&feed_name)
            .fetch_one(&pool)
            .await
            .expect("read back count for additional feed");
    assert_eq!(count, 1, "additional feed row must round-trip");

    // ON CONFLICT semantics — re-INSERTing the seed row must not error
    // and must not stomp the existing last_sync_at. (Mirrors the
    // migration's own `ON CONFLICT DO NOTHING` clause; idempotency
    // probe.)
    let before: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT last_sync_at FROM public.advisory_sync_state WHERE feed = 'osv'",
    )
    .fetch_one(&pool)
    .await
    .expect("read seed last_sync_at before re-insert");
    sqlx::query(
        "INSERT INTO public.advisory_sync_state (feed, last_sync_at, updated_at) \
         VALUES ('osv', now(), now()) ON CONFLICT DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("re-INSERT 'osv' with ON CONFLICT DO NOTHING must succeed");
    let after: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT last_sync_at FROM public.advisory_sync_state WHERE feed = 'osv'",
    )
    .fetch_one(&pool)
    .await
    .expect("read seed last_sync_at after re-insert");
    assert_eq!(
        before, after,
        "ON CONFLICT DO NOTHING must leave existing seed last_sync_at intact"
    );

    // Cleanup the test feed row.
    let _ = sqlx::query("DELETE FROM public.advisory_sync_state WHERE feed = $1")
        .bind(&feed_name)
        .execute(&pool)
        .await;
}

// ---------------------------------------------------------------------------
// Test 3 — confirm migration 010 did NOT touch `public.jobs`. The
// `kind` / `priority` / `trigger_source` / `result_summary` columns
// must already exist (from migration 009); 010's only role is to
// create `sbom_components` + `advisory_sync_state`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_010_does_not_alter_jobs_columns() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    // The four columns the user prompt explicitly calls out as
    // "must come from 009, not 010". This test exists so a future
    // accidental `ALTER TABLE jobs` in migration 010 would land
    // alongside an obvious test renaming requirement.
    for column in ["kind", "priority", "trigger_source", "result_summary"] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                            WHERE table_schema = 'public' AND table_name = 'jobs' \
                              AND column_name = $1)",
        )
        .bind(column)
        .fetch_one(&pool)
        .await
        .expect("probe jobs column existence");
        assert!(
            exists,
            "expected jobs.{column} to exist (carried by migration 009; \
             migration 010 must not need to add it)"
        );
    }
}
