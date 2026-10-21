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
//! The rows this reader returns carry **no typed event**. The hash is
//! recomputed from the `event_data` payload as the column holds it, so
//! nothing on this path deserializes a `DomainEvent` and chain
//! verification does not depend on whether today's types can still
//! decode a stored payload.
//!
//! The shared chain-read helpers (`retention_stream_id`, `to_event_hash`,
//! `sealed_record_from_row`) are reused from
//! [`crate::event_chain_head_reader`] — the same parsing the emitter and
//! the rest of the read path use, so the two read adapters agree
//! byte-for-byte on the `StreamSealed` shape and the 32-byte hash check.

use sqlx::{PgPool, Row};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{ChainRow, SealedStreamRecord};
use hort_domain::ports::event_chain_reader::EventChainReaderPort;
use hort_domain::ports::BoxFuture;

use crate::event_chain_head_reader::{retention_stream_id, sealed_record_from_row, to_event_hash};

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
                // Exactly the columns the canonical hash binds, plus the
                // two `bytea` chain columns it is checked against.
                // `global_position` and `stored_at` are deliberately
                // absent: they are store-assigned and excluded from the
                // hash by design, so reading them would widen the
                // verifier's input past what it attests.
                let rows = sqlx::query(
                    r#"SELECT
                           event_id, stream_id, stream_category, stream_position,
                           event_type, event_version, event_data,
                           correlation_id, causation_id, actor_type, actor_id,
                           actor_source_file, actor_spec_digest,
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
                    // Every field is taken straight off the row, in the
                    // form the column holds it: the canonical hash binds
                    // the stored bytes, never a re-serialization of a
                    // typed `Actor` or `DomainEvent`. Nothing here
                    // deserializes the payload — the verifier recomputes
                    // the hash from `event_data` itself, so a row whose
                    // payload today's types can no longer decode is still
                    // verifiable. (While this read went through
                    // `PersistedEvent::try_from`, such a row failed with
                    // an operational error before the verifier reached
                    // the hash — the one tool that could prove the row
                    // intact refused to run on it.)
                    let prev: Vec<u8> = row.get("prev_event_hash");
                    let hash: Vec<u8> = row.get("event_hash");
                    let stream_position: i64 = row.get("stream_position");
                    let event_version: i32 = row.get("event_version");
                    after_position = stream_position;
                    out.push(ChainRow {
                        event_data: row.get("event_data"),
                        event_id: row.get("event_id"),
                        stream_id: stream_id.to_string(),
                        stream_category: row.get("stream_category"),
                        stream_position: stream_position as u64,
                        event_type: row.get("event_type"),
                        event_version: event_version as u32,
                        correlation_id: row.get("correlation_id"),
                        causation_id: row.get("causation_id"),
                        actor_type: row.get("actor_type"),
                        actor_id: row.get("actor_id"),
                        actor_source_file: row.get("actor_source_file"),
                        actor_spec_digest: row.get("actor_spec_digest"),
                        stored_prev: to_event_hash(&prev, "prev_event_hash")?,
                        stored_hash: to_event_hash(&hash, "event_hash")?,
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
        crate::test_support::migrate_or_panic(&pool).await;
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
                    .all(|w| w[0].stream_position < w[1].stream_position),
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
