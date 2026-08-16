//! PostgreSQL adapter for [`ContentFirstSeenPort`] — the content-level
//! `first_seen_at` age projection (ADR 0054).
//!
//! Table: `content_first_seen` (`migrations/019_content_first_seen.sql`).
//! One row per SHA-256 content hash, owned by no repository, referenced
//! by no foreign key, deleted by nothing.
//!
//! # The minimum is computed by the database, not by this adapter
//!
//! `observe` is a single statement:
//!
//! ```sql
//! INSERT INTO content_first_seen (content_hash, first_seen_at)
//! VALUES ($1, $2)
//! ON CONFLICT (content_hash) DO UPDATE
//!     SET first_seen_at = LEAST(content_first_seen.first_seen_at,
//!                               EXCLUDED.first_seen_at)
//!     WHERE content_first_seen.first_seen_at > EXCLUDED.first_seen_at
//! ```
//!
//! `ON CONFLICT DO UPDATE` takes a row lock and re-reads the latest
//! committed version of the conflicting row before evaluating both the
//! `WHERE` guard and `LEAST`, so concurrent `observe` calls for the
//! same hash serialise on that row and each applies its comparison
//! against the value the other committed. The stored value is therefore
//! the minimum over all observations regardless of arrival order, with
//! no lost update. This is the whole reason the comparison may not live
//! in application code: a read-then-write would let two concurrent
//! ingests of the same content — the normal case across repositories —
//! both read "absent" and both write their own instant.
//!
//! The `WHERE` guard is a bloat control, not a correctness device:
//! without it, every re-ingest of already-seen content writes a new row
//! version that changes nothing. With it, the common path (a later
//! observation) updates no row at all. Correctness is unaffected
//! because the guard admits exactly the cases in which `LEAST` would
//! have chosen the incoming value.
//!
//! # Statement-level atomicity is sufficient; no transaction is opened
//!
//! The operation touches one row of one table. Wrapping it in an
//! explicit transaction would add a round trip and change nothing:
//! a single statement is already atomic, and there is no second write
//! that must land or fail with it.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use hort_domain::error::DomainResult;
use hort_domain::ports::content_first_seen::ContentFirstSeenPort;
use hort_domain::types::ContentHash;

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`ContentFirstSeenPort`].
///
/// Thin wrapper over a `PgPool`; no per-instance state beyond the pool.
/// Construction is cheap (no I/O).
pub struct PgContentFirstSeen {
    pool: PgPool,
}

impl PgContentFirstSeen {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ContentFirstSeenPort for PgContentFirstSeen {
    fn observe(
        &self,
        content_hash: &ContentHash,
        observed_at: DateTime<Utc>,
    ) -> BoxFuture<'_, DomainResult<()>> {
        // Copied out of the borrow so the returned future is bound only
        // to `&self` (the port's elided return lifetime), matching every
        // other adapter that takes a borrowed hash.
        let hash = content_hash.as_ref().to_string();
        Box::pin(async move {
            sqlx::query(
                r#"INSERT INTO content_first_seen (content_hash, first_seen_at)
                   VALUES ($1, $2)
                   ON CONFLICT (content_hash) DO UPDATE
                       SET first_seen_at = LEAST(content_first_seen.first_seen_at,
                                                 EXCLUDED.first_seen_at)
                       WHERE content_first_seen.first_seen_at > EXCLUDED.first_seen_at"#,
            )
            .bind(&hash)
            .bind(observed_at)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "content_first_seen", &hash))?;
            Ok(())
        })
    }

    fn first_seen(
        &self,
        content_hash: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Option<DateTime<Utc>>>> {
        let hash = content_hash.as_ref().to_string();
        Box::pin(async move {
            let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
                "SELECT first_seen_at FROM content_first_seen WHERE content_hash = $1",
            )
            .bind(&hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "content_first_seen", &hash))?;
            Ok(row.map(|(ts,)| ts))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const HASH_B: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    const HASH_C: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    fn hash(s: &str) -> ContentHash {
        s.parse().expect("valid sha256 hex")
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    // -- pure unit -----------------------------------------------------

    #[test]
    fn adapter_implements_port() {
        fn _assert_port<T: ContentFirstSeenPort>() {}
        _assert_port::<PgContentFirstSeen>();
    }

    #[tokio::test]
    async fn new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgContentFirstSeen::new(pool);
    }

    // -- DB-backed integration tests -----------------------------------
    //
    // Skipped (silent return) when `DATABASE_URL` is unset — mirrors
    // `refcount_reconcile.rs` / `pg_content_reference_repo.rs`. Each
    // test carries `#[serial(hort_pg_db)]` per the crate-wide
    // parallel-safety contract.

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    /// A first observation creates the record verbatim.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn first_observation_creates_the_record() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = PgContentFirstSeen::new(pool.clone());

        assert_eq!(adapter.first_seen(&hash(HASH_A)).await.unwrap(), None);
        adapter.observe(&hash(HASH_A), at(1_000)).await.unwrap();
        assert_eq!(
            adapter.first_seen(&hash(HASH_A)).await.unwrap(),
            Some(at(1_000))
        );
    }

    /// A LATER observation must not move the record forward — the
    /// second ingest of already-resident content (the cross-repository
    /// registration case) keeps the earlier evidence.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn later_observation_does_not_move_the_record() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = PgContentFirstSeen::new(pool.clone());

        adapter.observe(&hash(HASH_A), at(1_000)).await.unwrap();
        adapter.observe(&hash(HASH_A), at(5_000)).await.unwrap();
        assert_eq!(
            adapter.first_seen(&hash(HASH_A)).await.unwrap(),
            Some(at(1_000))
        );
    }

    /// An EARLIER observation moves the record back. Together with the
    /// test above this is the `min`, and it is the reason the two
    /// minting paths need no ordering guarantee between them.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn earlier_observation_moves_the_record_back() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = PgContentFirstSeen::new(pool.clone());

        adapter.observe(&hash(HASH_A), at(5_000)).await.unwrap();
        adapter.observe(&hash(HASH_A), at(1_000)).await.unwrap();
        assert_eq!(
            adapter.first_seen(&hash(HASH_A)).await.unwrap(),
            Some(at(1_000))
        );
    }

    /// The acceptance criterion stated as a single assertion: two
    /// ingests of the same content leave ONE row holding the earlier
    /// instant, whichever order they arrive in.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn two_ingests_leave_one_row_with_the_earlier_instant() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = PgContentFirstSeen::new(pool.clone());

        // Ascending arrival on HASH_A, descending on HASH_B.
        adapter.observe(&hash(HASH_A), at(1_000)).await.unwrap();
        adapter.observe(&hash(HASH_A), at(4_000)).await.unwrap();
        adapter.observe(&hash(HASH_B), at(4_000)).await.unwrap();
        adapter.observe(&hash(HASH_B), at(1_000)).await.unwrap();

        let rows: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT content_hash, first_seen_at FROM content_first_seen \
             WHERE content_hash = ANY($1) ORDER BY content_hash",
        )
        .bind(vec![HASH_A.to_string(), HASH_B.to_string()])
        .fetch_all(&pool)
        .await
        .expect("read rows");

        assert_eq!(rows.len(), 2, "one row per content hash, not per ingest");
        for (_, ts) in rows {
            assert_eq!(ts, at(1_000));
        }
    }

    /// Concurrent observations of the same hash converge on the
    /// minimum. The interleaving is not controlled — the assertion
    /// holds because the SQL, not the ordering, decides the outcome.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn concurrent_observations_converge_on_the_minimum() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = std::sync::Arc::new(PgContentFirstSeen::new(pool.clone()));

        // Instants issued in a deliberately shuffled order so the
        // smallest is neither first nor last to be spawned.
        let instants = [5_000i64, 9_000, 1_000, 7_000, 3_000, 1_000, 8_000, 2_000];
        let mut handles = Vec::new();
        for secs in instants {
            let a = std::sync::Arc::clone(&adapter);
            handles.push(tokio::spawn(async move {
                a.observe(&hash(HASH_C), at(secs)).await
            }));
        }
        for h in handles {
            h.await.expect("task joined").expect("observe succeeded");
        }

        assert_eq!(
            adapter.first_seen(&hash(HASH_C)).await.unwrap(),
            Some(at(1_000)),
            "the minimum survives concurrent writers"
        );
        let count: (i64,) =
            sqlx::query_as("SELECT count(*) FROM content_first_seen WHERE content_hash = $1")
                .bind(HASH_C)
                .fetch_one(&pool)
                .await
                .expect("count rows");
        assert_eq!(count.0, 1, "one row per hash under concurrency");
    }

    /// The record is not tied to any repository or artifact row:
    /// deleting the last per-repo row for a hash (which cascades
    /// through `artifacts` / `content_references`) leaves it intact.
    /// This is the ADR 0054 survival requirement.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn record_survives_deletion_of_the_last_per_repo_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = PgContentFirstSeen::new(pool.clone());

        let repo = uuid::Uuid::new_v4();
        let key = format!("it-first-seen-{}", repo.simple());
        sqlx::query(
            r#"INSERT INTO repositories (
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
        .bind(repo)
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .execute(&pool)
        .await
        .expect("seed repo");

        let artifact = uuid::Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key
               ) VALUES (
                   $1, $2, 'a', 'a', '1.0.0', $3,
                   0, $4, 'application/octet-stream', $3
               )"#,
        )
        .bind(artifact)
        .bind(repo)
        .bind(format!("artifacts/a-{}", artifact.simple()))
        .bind(HASH_A)
        .execute(&pool)
        .await
        .expect("seed artifact");

        adapter.observe(&hash(HASH_A), at(1_000)).await.unwrap();

        // Drop the whole repository — the strongest per-repo deletion
        // available, cascading every artifact row for that hash.
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(&pool)
            .await
            .expect("delete repo");
        let remaining: (i64,) = sqlx::query_as("SELECT count(*) FROM artifacts WHERE id = $1")
            .bind(artifact)
            .fetch_one(&pool)
            .await
            .expect("count artifacts");
        assert_eq!(remaining.0, 0, "the per-repo row is gone");

        assert_eq!(
            adapter.first_seen(&hash(HASH_A)).await.unwrap(),
            Some(at(1_000)),
            "the content-level age record outlives every per-repo row"
        );
    }

    /// The shape CHECK rejects an out-of-band writer that would create
    /// a second, differently-cased record for the same bytes.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn shape_check_rejects_a_non_canonical_hash() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let upper = HASH_A.to_ascii_uppercase();
        let err = sqlx::query(
            "INSERT INTO content_first_seen (content_hash, first_seen_at) VALUES ($1, now())",
        )
        .bind(&upper)
        .execute(&pool)
        .await
        .expect_err("the shape CHECK rejects a non-canonical hash");
        assert!(
            err.to_string()
                .contains("content_first_seen_hash_shape_check"),
            "expected the shape CHECK to fire, got: {err}"
        );
    }

    /// A closed pool surfaces as a `DomainError` rather than a panic —
    /// the error arm both methods map through.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn closed_pool_surfaces_a_domain_error() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = PgContentFirstSeen::new(pool.clone());
        pool.close().await;

        assert!(adapter.observe(&hash(HASH_A), at(1)).await.is_err());
        assert!(adapter.first_seen(&hash(HASH_A)).await.is_err());
    }
}
