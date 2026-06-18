//! PostgreSQL adapter for [`TerminalStreamReader`] — the
//! audit-retention stream-enumeration port (ADR 0020).
//!
//! Enumerates every event stream with the per-candidate facts the
//! `hort-app` `EventStoreRetentionUseCase` needs to apply the
//! per-category seal rule (terminal-gated vs age-gated) and the
//! audit-retention floor: the rendered `stream_id`, its
//! [`StreamCategory`], the oldest event's `stored_at` (the floor
//! anchor), the newest event's `stored_at`, and the tail (max
//! `stream_position`) event's `event_type`.
//!
//! Purely additive: a brand-new adapter for a brand-new (additive)
//! port. No existing adapter or port signature is touched — the frozen
//! [`crate::event_store::PgEventStore`] (and the `seal_and_remove`
//! chokepoint it owns) is left exactly as shipped; the use case routes
//! seals through that chokepoint, never through this reader.
//!
//! # The enumeration query (one set-based aggregate)
//!
//! One grouped scan over `events`:
//!
//! - `min(stored_at)` / `max(stored_at)` per `stream_id` — the floor
//!   anchor + the newest-event timestamp.
//! - The `event_type` of the row with the **maximum** `stream_position`
//!   per `stream_id` — the terminal-gate input. `DISTINCT ON
//!   (stream_id) … ORDER BY stream_id, stream_position DESC` gives the
//!   tail row directly (the same shape `seal_and_remove`'s tail read
//!   uses, lifted to a set).
//! - The meta-stream `StreamId::eventstore_retention()` is excluded in
//!   SQL (`WHERE stream_id <> $1`) — double defence-in-depth: the use
//!   case re-asserts the guard. Sealing it would truncate the audit
//!   trail of every seal.
//!
//! The `stream_id` text column is parsed back through
//! [`StreamId::from_str`] so the [`StreamCategory`] is derived from the
//! single canonical parser (no second `stream_category`-text → enum
//! mapping that could drift from `StreamId`'s own `FromStr`). A row
//! whose `stream_id` does not parse (corrupt / pre-convention legacy)
//! is skipped with a `tracing::warn!` rather than aborting the whole
//! enumeration — one bad row never blocks retention of every other
//! stream (and the use case's own guards are a further backstop).

use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use hort_domain::error::DomainResult;
use hort_domain::events::StreamId;
use hort_domain::ports::terminal_stream_reader::{TerminalStreamCandidate, TerminalStreamReader};

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`TerminalStreamReader`].
///
/// Thin wrapper over a `PgPool`; no per-instance state beyond the
/// pool. Construction is cheap (no I/O).
pub struct PgTerminalStreamReader {
    pool: PgPool,
}

impl PgTerminalStreamReader {
    /// Wrap a `PgPool`. Cheap — no I/O.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Raw row shape of the enumeration aggregate.
#[derive(FromRow)]
struct CandidateRow {
    stream_id: String,
    first_event_at: DateTime<Utc>,
    last_event_at: DateTime<Utc>,
    last_event_type: String,
}

impl TerminalStreamReader for PgTerminalStreamReader {
    fn list_terminal_candidates(
        &self,
    ) -> BoxFuture<'_, DomainResult<Vec<TerminalStreamCandidate>>> {
        let meta_stream_id = StreamId::eventstore_retention().to_string();
        Box::pin(async move {
            // One grouped scan. The tail event_type comes from a
            // `DISTINCT ON (stream_id) … ORDER BY stream_id,
            // stream_position DESC` subquery (the tail row), joined to
            // the per-stream min/max(stored_at) aggregate. The
            // never-deleted audit-meta stream is excluded in SQL
            // (double defence-in-depth with the use case's guard).
            let rows: Vec<CandidateRow> = sqlx::query_as(
                r#"
                SELECT agg.stream_id        AS stream_id,
                       agg.first_event_at   AS first_event_at,
                       agg.last_event_at    AS last_event_at,
                       tail.last_event_type AS last_event_type
                FROM (
                    SELECT stream_id,
                           min(stored_at) AS first_event_at,
                           max(stored_at) AS last_event_at
                    FROM events
                    WHERE stream_id <> $1
                    GROUP BY stream_id
                ) AS agg
                JOIN (
                    SELECT DISTINCT ON (stream_id)
                           stream_id,
                           event_type AS last_event_type
                    FROM events
                    WHERE stream_id <> $1
                    ORDER BY stream_id, stream_position DESC
                ) AS tail
                  ON tail.stream_id = agg.stream_id
                ORDER BY agg.stream_id
                "#,
            )
            .bind(&meta_stream_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "terminal_stream_reader", "list_candidates"))?;

            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                // Derive the category from the single canonical parser.
                // A non-parsing stream_id is skipped (warn) — one bad
                // legacy row never blocks retention of the rest.
                let stream = match StreamId::from_str(&row.stream_id) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(
                            stream_id = %row.stream_id,
                            error = %e,
                            "terminal-candidate stream_id did not parse — \
                             skipped from the retention enumeration (one \
                             bad row never blocks the sweep)"
                        );
                        continue;
                    }
                };
                out.push(TerminalStreamCandidate {
                    stream_id: row.stream_id,
                    category: stream.category,
                    first_event_at: row.first_event_at,
                    last_event_at: row.last_event_at,
                    last_event_type: row.last_event_type,
                });
            }
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use uuid::Uuid;

    use hort_domain::events::StreamCategory;

    // -- pure unit -----------------------------------------------------

    #[test]
    fn adapter_implements_port() {
        fn _assert_port<T: TerminalStreamReader>() {}
        _assert_port::<PgTerminalStreamReader>();
    }

    #[tokio::test]
    async fn pg_terminal_stream_reader_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgTerminalStreamReader::new(pool);
    }

    // -- DB-backed integration tests -----------------------------------
    //
    // Skipped (silent return) when `DATABASE_URL` is unset — mirrors
    // `purge_gc.rs` / `refcount_reconcile.rs`. Events are NOT FK'd to
    // repositories, so each test sweeps the exact stream ids it seeds
    // on entry AND exit (the enumeration query is global — a leftover
    // row from another test would otherwise show up as a candidate).
    // `#[serial(hort_pg_db)]` because the hort-adapters-postgres `--lib`
    // DB suite shares one database with no per-test isolation
    // (commit ed79360a).

    use std::env;

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    /// Append a minimal event to an arbitrary stream. `prev`/
    /// `event_hash` are 32-byte fillers — these tests exercise the
    /// enumeration aggregate, not the chain verifier, so any 32-byte
    /// value satisfies the width CHECK.
    async fn append_event(
        pool: &PgPool,
        stream_id: &str,
        stream_category: &str,
        stream_position: i64,
        event_type: &str,
        stored_at: DateTime<Utc>,
    ) {
        sqlx::query(
            r#"INSERT INTO events (
                   stream_id, stream_category, stream_position, event_type,
                   event_data, correlation_id, actor_type, stored_at,
                   prev_event_hash, event_hash
               ) VALUES (
                   $1, $2, $3, $4,
                   '{}'::jsonb, gen_random_uuid(), 'system', $5,
                   '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
                   '\x1111111111111111111111111111111111111111111111111111111111111111'::bytea
               )"#,
        )
        .bind(stream_id)
        .bind(stream_category)
        .bind(stream_position)
        .bind(event_type)
        .bind(stored_at)
        .execute(pool)
        .await
        .expect("append event");
    }

    async fn purge_stream(pool: &PgPool, stream_id: &str) {
        let _ = sqlx::query("DELETE FROM events WHERE stream_id = $1")
            .bind(stream_id)
            .execute(pool)
            .await;
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    #[ignore = "requires DATABASE_URL"]
    async fn enumerates_min_max_and_tail_event_type_and_parses_category() {
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL must be set for #[ignore]'d DB tests");
        let aid = Uuid::new_v4();
        let sid = StreamId::artifact(aid).to_string();
        purge_stream(&pool, &sid).await;

        // Three events: oldest @100 (Ingested), middle @200, tail
        // (max stream_position) @300 = ArtifactPurged.
        append_event(&pool, &sid, "artifact", 0, "ArtifactIngested", ts(100)).await;
        append_event(&pool, &sid, "artifact", 1, "ArtifactQuarantined", ts(200)).await;
        append_event(&pool, &sid, "artifact", 2, "ArtifactPurged", ts(300)).await;

        let reader = PgTerminalStreamReader::new(pool.clone());
        let cands = reader.list_terminal_candidates().await.unwrap();
        let c = cands
            .iter()
            .find(|c| c.stream_id == sid)
            .expect("seeded stream is enumerated");
        assert_eq!(c.category, StreamCategory::Artifact);
        assert_eq!(c.first_event_at, ts(100));
        assert_eq!(c.last_event_at, ts(300));
        assert_eq!(c.last_event_type, "ArtifactPurged");

        purge_stream(&pool, &sid).await;
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    #[ignore = "requires DATABASE_URL"]
    async fn meta_stream_is_excluded_in_sql() {
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL must be set for #[ignore]'d DB tests");
        let meta = StreamId::eventstore_retention().to_string();
        purge_stream(&pool, &meta).await;
        append_event(&pool, &meta, "admin", 0, "StreamSealed", ts(100)).await;

        let reader = PgTerminalStreamReader::new(pool.clone());
        let cands = reader.list_terminal_candidates().await.unwrap();
        assert!(
            cands.iter().all(|c| c.stream_id != meta),
            "the never-deleted audit-meta stream must be excluded by the \
             enumeration query (double defence-in-depth)"
        );

        purge_stream(&pool, &meta).await;
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    #[ignore = "requires DATABASE_URL"]
    async fn tail_is_max_stream_position_not_max_stored_at() {
        // A later stream_position with an EARLIER stored_at must still
        // be the tail (clock skew tolerance — the architect note on
        // PersistedEvent.stored_at being non-monotonic).
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL must be set for #[ignore]'d DB tests");
        let aid = Uuid::new_v4();
        let sid = StreamId::artifact(aid).to_string();
        purge_stream(&pool, &sid).await;

        append_event(&pool, &sid, "artifact", 0, "ArtifactIngested", ts(500)).await;
        // Higher stream_position, EARLIER stored_at.
        append_event(&pool, &sid, "artifact", 1, "ArtifactPurged", ts(100)).await;

        let reader = PgTerminalStreamReader::new(pool.clone());
        let cands = reader.list_terminal_candidates().await.unwrap();
        let c = cands.iter().find(|c| c.stream_id == sid).unwrap();
        assert_eq!(
            c.last_event_type, "ArtifactPurged",
            "tail is the max-stream_position row, not the max-stored_at row"
        );
        // first_event_at is min(stored_at) = 100 (the floor anchor is
        // the OLDEST stored_at regardless of position).
        assert_eq!(c.first_event_at, ts(100));

        purge_stream(&pool, &sid).await;
    }
}
