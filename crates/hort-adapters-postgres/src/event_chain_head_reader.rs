//! `EventChainHeadReaderPort` Postgres adapter — the external-anchor
//! emission half (ADR 0004).
//!
//! Snapshots the live event store for checkpoint emission: every live
//! stream's `(stream_id, final_stream_position, head_event_hash)`, the
//! consistent-cut `max_global_position`, and the `StreamSealed` records
//! on the never-deleted `StreamId::eventstore_retention()` audit-meta
//! stream (the derived `admin-<v5-uuid>` id; B8 decision a2) since the
//! previous checkpoint.
//!
//! ## Read posture (spec §8.2 + governance)
//!
//! `SELECT`-only on the **runtime DML DSN** (the `hort_app_role`
//! equivalent that holds only `SELECT`/`INSERT` on `events`) — never
//! DDL, never a write to `events`. This mirrors exactly the Item-3
//! verifier's own read posture
//! (`crates/hort-server/src/cli/verify_event_chain.rs`) and reuses the
//! same bounded per-stream head shape. The `EventStore` port is
//! **neither used nor widened** (spec §14 R4 / governance) — this
//! adapter issues its own bounded `SELECT` that additionally returns the
//! `event_hash` chain column `PersistedEvent` cannot carry, exactly as
//! the verifier does. Reading one more column in this adapter's own
//! query widens no port and changes no trait.
//!
//! ## Consistent cut
//!
//! The head snapshot + `max_global_position` + the `StreamSealed` scan
//! are taken inside one read transaction (`REPEATABLE READ`) so the
//! checkpoint binds a coherent point-in-time (spec §6.2 "a consistent
//! cut"); a stream that grew a row between the head read and the
//! global-position read cannot smear the cut.
//!
//! ## `StreamSealed`
//!
//! The `DomainEvent::StreamSealed` variant is emitted (ADR 0002 + 0004)
//! to the `StreamId::eventstore_retention()` stream. `sealed_since_previous`
//! therefore carries one `SealedStreamRecord` per seal since the
//! previous checkpoint — empty only on a DB where nothing has been
//! sealed yet (still a valid, expected result the emitter handles
//! cleanly).

use sqlx::{PgPool, Row};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{DomainEvent, EventHash, SealedStreamRecord, StreamHead, StreamId};
use hort_domain::ports::event_chain_head_reader::{EventChainHeadReaderPort, LiveChainSnapshot};
use hort_domain::ports::BoxFuture;

/// The never-deleted audit-meta stream id the §2.3 `StreamSealed`
/// tombstones (and F-9 Part-3 destructive-task audit) live on.
///
/// Derives from [`StreamId::eventstore_retention`] — not a hand-pinned
/// literal. The wire form is `admin-<v5-uuid>` (`StreamCategory::Admin`,
/// the deterministic UUIDv5 over the `"eventstore-retention"` label),
/// which is exactly what the F-2 chained-append emitter (B9) /
/// destructive-task router (B10) produces. The verifier verdict
/// logic, chain computation, and `SealedGap`-vs-`Broken` rule are
/// byte-unchanged — only the stream-identity value is derived.
pub(crate) fn retention_stream_id() -> String {
    StreamId::eventstore_retention().to_string()
}

/// `EventChainHeadReaderPort` over a runtime-DML `PgPool`.
pub struct PgEventChainHeadReader {
    pool: PgPool,
}

impl PgEventChainHeadReader {
    /// Construct from the runtime DML pool (the same pool every other
    /// runtime adapter uses — `SELECT`/`INSERT` only).
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Convert a stored 32-byte `bytea` chain column to the domain
/// [`EventHash`]. A wrong width is an operational invariant breach (the
/// schema `CHECK (octet_length(event_hash) = 32)` should make this
/// unreachable) — surfaced as `Err`, never silently coerced.
pub(crate) fn to_event_hash(bytes: &[u8], col: &str) -> DomainResult<EventHash> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        DomainError::Invariant(format!(
            "{col} is {} bytes, expected 32 (schema CHECK should make this \
             unreachable)",
            bytes.len()
        ))
    })?;
    Ok(EventHash(arr))
}

/// Parse a stored `StreamSealed` event payload (the `event_data->'data'`
/// JSON) into the verifier-facing [`SealedStreamRecord`]. The stored
/// envelope is `{"type":"StreamSealed","data":{…}}`
/// (`serialize_event_data`); deserialize the typed event the same way
/// the rest of the read path does, then project the two fields the
/// checkpoint binds. A row that does not deserialize as `StreamSealed`
/// is an operational corruption (`Err`) — not silently skipped.
pub(crate) fn sealed_record_from_row(
    event_data: &serde_json::Value,
) -> DomainResult<SealedStreamRecord> {
    let data = event_data.get("data").ok_or_else(|| {
        DomainError::Invariant("StreamSealed event_data missing 'data' field".into())
    })?;
    // `{event_type: data}` is the serde enum envelope the rest of the
    // read path reconstructs (mappers::deserialize_event_data); reuse
    // the exact shape so this adapter and the event store agree.
    let envelope = serde_json::json!({ "StreamSealed": data });
    let event: DomainEvent = serde_json::from_value(envelope)
        .map_err(|e| DomainError::Invariant(format!("failed to deserialize StreamSealed: {e}")))?;
    match event {
        DomainEvent::StreamSealed(s) => Ok(SealedStreamRecord {
            sealed_stream_id: s.sealed_stream_id,
            final_event_hash: EventHash(s.final_event_hash),
        }),
        other => Err(DomainError::Invariant(format!(
            "expected StreamSealed on {}, got {}",
            retention_stream_id(),
            other.event_type()
        ))),
    }
}

impl EventChainHeadReaderPort for PgEventChainHeadReader {
    fn snapshot_live_chain(&self) -> BoxFuture<'_, DomainResult<LiveChainSnapshot>> {
        Box::pin(async move {
            // One REPEATABLE READ transaction → a consistent cut
            // (spec §6.2). All three reads see the same snapshot.
            let mut tx =
                self.pool.begin().await.map_err(|e| {
                    DomainError::Invariant(format!("begin snapshot tx failed: {e}"))
                })?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(&mut *tx)
                .await
                .map_err(|e| DomainError::Invariant(format!("set repeatable read failed: {e}")))?;

            // (1) Per-stream head: the row with the max stream_position
            //     for each stream_id, and that row's event_hash. Same
            //     bounded shape the Item-3 verifier uses (DISTINCT ON +
            //     ORDER BY stream_position DESC). The id set is small
            //     (thousands of streams, spec §6.2) — one query.
            let head_rows = sqlx::query(
                r#"SELECT DISTINCT ON (stream_id)
                       stream_id, stream_position, event_hash
                   FROM events
                   ORDER BY stream_id, stream_position DESC"#,
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| {
                DomainError::Invariant(format!("reading live stream heads failed: {e}"))
            })?;

            let mut heads = Vec::with_capacity(head_rows.len());
            for row in &head_rows {
                let stream_id: String = row.get("stream_id");
                let pos: i64 = row.get("stream_position");
                let hash_bytes: Vec<u8> = row.get("event_hash");
                heads.push(StreamHead {
                    stream_id,
                    final_stream_position: pos as u64,
                    head_event_hash: to_event_hash(&hash_bytes, "event_hash")?,
                });
            }

            // (2) The consistent-cut marker: max global_position.
            //     COALESCE so an empty table yields 0, not NULL.
            let max_gp: i64 =
                sqlx::query("SELECT COALESCE(MAX(global_position), 0) AS max_gp FROM events")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|e| {
                        DomainError::Invariant(format!("reading max global_position failed: {e}"))
                    })?
                    .get("max_gp");

            // (3) StreamSealed records on the audit-meta stream (ADR 0004).
            //     May be empty on a DB where nothing has been sealed yet —
            //     valid result. Ordered for determinism.
            let sealed_rows = sqlx::query(
                r#"SELECT event_data
                   FROM events
                   WHERE stream_id = $1 AND event_type = 'StreamSealed'
                   ORDER BY stream_position ASC"#,
            )
            .bind(retention_stream_id())
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| {
                DomainError::Invariant(format!("reading StreamSealed records failed: {e}"))
            })?;

            let mut sealed = Vec::with_capacity(sealed_rows.len());
            for row in &sealed_rows {
                let event_data: serde_json::Value = row.get("event_data");
                sealed.push(sealed_record_from_row(&event_data)?);
            }

            // Read-only — commit (no writes; commit releases the snapshot).
            tx.commit()
                .await
                .map_err(|e| DomainError::Invariant(format!("commit snapshot tx failed: {e}")))?;

            Ok(LiveChainSnapshot::new(heads, max_gp as u64, sealed))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::events::StreamSealed;
    use serial_test::serial;
    use uuid::Uuid;

    // ---- pure helpers (no DB) ------------------------------------------

    #[test]
    fn to_event_hash_accepts_32_bytes() {
        assert_eq!(
            to_event_hash(&[7u8; 32], "event_hash").unwrap(),
            EventHash([7u8; 32])
        );
    }

    #[test]
    fn to_event_hash_rejects_wrong_width() {
        let e = to_event_hash(&[0u8; 16], "event_hash").unwrap_err();
        assert!(e.to_string().contains("expected 32"));
    }

    #[test]
    fn sealed_record_parses_the_stored_envelope() {
        // The stored shape is {"type":"StreamSealed","data":{…}} —
        // build it the way `serialize_event_data` would and assert the
        // projection.
        let ss = StreamSealed {
            sealed_stream_id: "authorization-00000000-0000-0000-0000-000000000001".into(),
            sealed_stream_category: "authorization".into(),
            final_stream_position: 4,
            final_event_hash: [0xab; 32],
            event_count: 5,
            retention_policy_id: Uuid::nil(),
            actor_id: None,
        };
        // serde enum form → {"StreamSealed": {…}} → take inner as `data`.
        let enum_form = serde_json::to_value(DomainEvent::StreamSealed(ss.clone())).unwrap();
        let data = enum_form.get("StreamSealed").unwrap().clone();
        let stored = serde_json::json!({ "type": "StreamSealed", "data": data });

        let rec = sealed_record_from_row(&stored).unwrap();
        assert_eq!(rec.sealed_stream_id, ss.sealed_stream_id);
        assert_eq!(rec.final_event_hash, EventHash([0xab; 32]));
    }

    #[test]
    fn sealed_record_rejects_missing_data() {
        let bad = serde_json::json!({ "type": "StreamSealed" });
        let e = sealed_record_from_row(&bad).unwrap_err();
        assert!(e.to_string().contains("missing 'data'"));
    }

    #[test]
    fn sealed_record_rejects_wrong_event_type_payload() {
        // `data` that does not deserialize as StreamSealed → Err
        // (operational corruption, not silently skipped).
        let bad = serde_json::json!({ "type": "StreamSealed", "data": { "nope": 1 } });
        let e = sealed_record_from_row(&bad).unwrap_err();
        assert!(e.to_string().contains("deserialize StreamSealed"));
    }

    #[test]
    fn retention_stream_id_is_derived_from_the_ctor() {
        // The audit-meta stream identity is
        // `StreamId::eventstore_retention().to_string()`
        // (`admin-<v5-uuid>`) — the single source of truth. The reader
        // const must DERIVE from the ctor, not be a hand-pinned literal
        // that happens to match. Pin the equivalence.
        assert_eq!(
            retention_stream_id(),
            StreamId::eventstore_retention().to_string()
        );
    }

    // ---- DB-backed (gated on DATABASE_URL; green locally without a DB) --
    //
    // Mirrors the Item-3 verifier's `maybe_pool()` early-return idiom
    // (`crates/hort-server/src/cli/verify_event_chain.rs`): no DATABASE_URL
    // ⇒ silent early return so `cargo test --workspace --lib` stays
    // green locally; Tier-2/CI sets DATABASE_URL and the body runs.

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
    async fn snapshot_live_chain_structural_invariants_hold() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        // Exercises the real SQL + the consistent-cut transaction
        // end-to-end. The shared CI DB carries rows other suites seeded
        // (and real tombstones sibling seal suites commit to the global
        // `eventstore_retention` stream — `#[serial(hort_pg_db)]` is
        // process-local and does not serialise across test binaries), so
        // assert the structural invariants that always hold rather than
        // exact emptiness.
        let reader = PgEventChainHeadReader::new(pool);
        let snap = reader.snapshot_live_chain().await.unwrap();
        assert!(snap.max_global_position >= snap.heads.len() as u64 || snap.heads.is_empty());
        // Post-Phase-B `sealed_since_previous` is NOT empty in a shared
        // DB. The invariant that still always holds: every record the
        // adapter returned parsed cleanly into a well-formed
        // `SealedStreamRecord` (non-empty `sealed_stream_id`) — the
        // StreamSealed read+parse path is exercised whether the stream
        // is empty or sibling-populated.
        assert!(snap
            .sealed_since_previous
            .iter()
            .all(|r| !r.sealed_stream_id.is_empty()));
    }
}
