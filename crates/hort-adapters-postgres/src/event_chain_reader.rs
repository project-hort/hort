//! `EventChainReaderPort` Postgres adapter — the offline-verifier read
//! path (ADR 0004).
//!
//! Moves the `hort-server verify-event-chain` subcommand's reads out of the
//! binary and behind the [`EventChainReaderPort`], so **all `sqlx` lives
//! in this adapter** and the verifier stays backend-agnostic (it depends
//! on `Arc<dyn EventChainReaderPort>`; an EventStoreDB/KurrentDB backend
//! implements the same port). Mirrors the emitter half's
//! [`PgEventChainHeadReader`](crate::event_chain_head_reader): `SELECT`-only
//! on the runtime DML DSN, bounded per-stream paging, the
//! `prev_event_hash`/`event_hash` chain columns `PersistedEvent` cannot
//! carry surfaced without widening `EventStore`.
//!
//! The shared chain-read helpers (`retention_stream_id`, `to_event_hash`,
//! `sealed_record_from_row`) are reused from
//! [`crate::event_chain_head_reader`] — the same parsing the emitter and
//! the rest of the read path use, so the two read adapters agree
//! byte-for-byte on the `StreamSealed` shape and the 32-byte hash check.

use sqlx::{PgPool, Row};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{ChainRow, PersistedEvent, SealedStreamRecord};
use hort_domain::ports::event_chain_reader::EventChainReaderPort;
use hort_domain::ports::BoxFuture;

use crate::event_chain_head_reader::{retention_stream_id, sealed_record_from_row, to_event_hash};
use crate::mappers::EventRow;

/// Bounded page size for per-stream reads — streams are paged so the
/// verifier never buffers the whole table.
const STREAM_PAGE: i64 = 1024;

/// `EventChainReaderPort` over a runtime-DML `PgPool`.
pub struct PgEventChainReader {
    pool: PgPool,
}

impl PgEventChainReader {
    /// Construct from the runtime DML pool (the same pool every other
    /// runtime adapter uses — `SELECT`/`INSERT` only, never DDL).
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl EventChainReaderPort for PgEventChainReader {
    fn list_stream_ids(
        &self,
        since_global: Option<u64>,
    ) -> BoxFuture<'_, DomainResult<Vec<String>>> {
        Box::pin(async move {
            // `--since-global N` selects every stream with any activity at
            // `global_position >= N` (`>=`, not `>`). Absent ⇒
            // no predicate ⇒ all streams (the predicate is omitted, not
            // faked with `>= 0`, so the "verify all" path is index-clean).
            let rows = match since_global {
                Some(n) => sqlx::query(
                    r#"SELECT DISTINCT stream_id
                       FROM events
                       WHERE global_position >= $1
                       ORDER BY stream_id ASC"#,
                )
                .bind(n as i64)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    DomainError::Invariant(format!(
                        "listing distinct stream ids (since-global): {e}"
                    ))
                })?,
                None => sqlx::query(
                    r#"SELECT DISTINCT stream_id
                       FROM events
                       ORDER BY stream_id ASC"#,
                )
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    DomainError::Invariant(format!(
                        "listing distinct stream ids (all streams): {e}"
                    ))
                })?,
            };
            Ok(rows
                .iter()
                .map(|r| r.get::<String, _>("stream_id"))
                .collect())
        })
    }

    fn read_stream_chain<'a>(
        &'a self,
        stream_id: &'a str,
    ) -> BoxFuture<'a, DomainResult<Vec<ChainRow>>> {
        Box::pin(async move {
            let mut out = Vec::new();
            let mut after_position: i64 = -1;
            loop {
                // Selects the `EventRow` columns plus the two `bytea` chain
                // columns `PersistedEvent` cannot carry — exactly the shape
                // the in-CLI verifier used, now adapter-local.
                let rows = sqlx::query(
                    r#"SELECT
                           event_id, stream_id, stream_category, stream_position,
                           global_position, event_type, event_version, event_data,
                           correlation_id, causation_id, actor_type, actor_id,
                           actor_source_file, actor_spec_digest, stored_at,
                           prev_event_hash, event_hash
                       FROM events
                       WHERE stream_id = $1
                         AND stream_position > $2
                       ORDER BY stream_position ASC
                       LIMIT $3"#,
                )
                .bind(stream_id)
                .bind(after_position)
                .bind(STREAM_PAGE)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| DomainError::Invariant(format!("reading stream {stream_id}: {e}")))?;

                if rows.is_empty() {
                    break;
                }
                let n = rows.len();
                for row in &rows {
                    let event_row = EventRow {
                        event_id: row.get("event_id"),
                        stream_id: row.get("stream_id"),
                        stream_category: row.get("stream_category"),
                        stream_position: row.get("stream_position"),
                        global_position: row.get("global_position"),
                        event_type: row.get("event_type"),
                        event_version: row.get("event_version"),
                        event_data: row.get("event_data"),
                        correlation_id: row.get("correlation_id"),
                        causation_id: row.get("causation_id"),
                        actor_type: row.get("actor_type"),
                        actor_id: row.get("actor_id"),
                        actor_source_file: row.get("actor_source_file"),
                        actor_spec_digest: row.get("actor_spec_digest"),
                        stored_at: row.get("stored_at"),
                    };
                    // The four actor columns + stream strings must be kept
                    // in their exact stored form (the canonical hash binds
                    // the stored bytes, not a re-serialization of the typed
                    // `Actor`) — clone before `try_from` consumes the row.
                    let stream_category = event_row.stream_category.clone();
                    let actor_type = event_row.actor_type.clone();
                    let actor_id = event_row.actor_id;
                    let actor_source_file = event_row.actor_source_file.clone();
                    let actor_spec_digest = event_row.actor_spec_digest.clone();
                    let prev: Vec<u8> = row.get("prev_event_hash");
                    let hash: Vec<u8> = row.get("event_hash");
                    let stored_prev = to_event_hash(&prev, "prev_event_hash")?;
                    let stored_hash = to_event_hash(&hash, "event_hash")?;
                    // `TryFrom<EventRow>` — the existing adapter
                    // deserialization path. A deserialization failure is an
                    // operational error (corrupt row not attributable to a
                    // chain mutation), surfaced as `Err`, not a chain break.
                    let persisted = PersistedEvent::try_from(event_row)?;
                    after_position = persisted.stream_position as i64;
                    out.push(ChainRow {
                        persisted,
                        stream_id: stream_id.to_string(),
                        stream_category,
                        actor_type,
                        actor_id,
                        actor_source_file,
                        actor_spec_digest,
                        stored_prev,
                        stored_hash,
                    });
                }
                if (n as i64) < STREAM_PAGE {
                    break;
                }
            }
            Ok(out)
        })
    }

    fn read_sealed_records(&self) -> BoxFuture<'_, DomainResult<Vec<SealedStreamRecord>>> {
        Box::pin(async move {
            let rows = sqlx::query(
                r#"SELECT event_data
                   FROM events
                   WHERE stream_id = $1 AND event_type = 'StreamSealed'
                   ORDER BY stream_position ASC"#,
            )
            .bind(retention_stream_id())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DomainError::Invariant(format!("reading StreamSealed records: {e}")))?;
            let mut out = Vec::with_capacity(rows.len());
            for row in &rows {
                let event_data: serde_json::Value = row.get("event_data");
                out.push(sealed_record_from_row(&event_data)?);
            }
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::events::{verify_stream_chain, StreamRows, StreamVerdict};
    use serial_test::serial;

    // ---- DB-backed (gated on DATABASE_URL; green locally without a DB) --
    //
    // Mirrors the `PgEventChainHeadReader` `maybe_pool()` idiom: no
    // DATABASE_URL ⇒ silent early return so `cargo test --lib`
    // stays green locally; Tier-2/CI sets DATABASE_URL and the body runs.
    // The shared CI DB carries rows other suites seeded, so the assertions
    // are structural invariants that always hold, not exact emptiness.

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn reader_methods_exercise_their_sql_paths() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let reader = PgEventChainReader::new(pool);

        // list_stream_ids: `SELECT DISTINCT … ORDER BY stream_id ASC` ⇒
        // strictly ascending (which proves both ordering and dedup).
        let ids = reader.list_stream_ids(None).await.unwrap();
        assert!(
            ids.windows(2).all(|w| w[0] < w[1]),
            "stream ids must be ascending and de-duplicated"
        );

        // since-global is a stream-selection filter ⇒ a subset of all.
        let since = reader.list_stream_ids(Some(u64::MAX)).await.unwrap();
        assert!(since.len() <= ids.len());

        // read_stream_chain: rows come back in ascending stream_position,
        // and every row maps cleanly into a pure-core view. A real
        // production stream is a valid chain, so verify_stream_chain must
        // not report Broken for it (the read fed the core correct inputs).
        if let Some(first) = ids.first() {
            let rows = reader.read_stream_chain(first).await.unwrap();
            assert!(
                rows.windows(2)
                    .all(|w| w[0].persisted.stream_position < w[1].persisted.stream_position),
                "rows ordered by ascending stream_position"
            );
            let views: Vec<_> = rows.iter().map(ChainRow::as_stream_row).collect();
            assert!(
                !matches!(
                    verify_stream_chain(&StreamRows::new(&views)),
                    StreamVerdict::Broken { .. }
                ),
                "a production stream read through the port is a valid chain"
            );
        }

        // read_sealed_records: every record parsed into a well-formed
        // SealedStreamRecord (the StreamSealed read+parse path is exercised
        // whether the audit-meta stream is empty or sibling-populated).
        let sealed = reader.read_sealed_records().await.unwrap();
        assert!(sealed.iter().all(|r| !r.sealed_stream_id.is_empty()));
    }
}
