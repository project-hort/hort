//! `EventChainHeadReaderPort` Postgres adapter — the external-anchor
//! emission half (ADR 0004).
//!
//! Snapshots the live event store for checkpoint emission: every live
//! stream's `(stream_id, final_stream_position, head_event_hash)`, the
//! consistent-cut `max_global_position`, and the `StreamSealed` records
//! on the never-deleted `StreamId::eventstore_retention()` audit-meta
//! stream (the derived `admin-<v5-uuid>` id) since the
//! previous **anchored** checkpoint.
//!
//! ## Read posture
//!
//! `SELECT`-only on the **runtime DML DSN** (the `hort_app_role`
//! equivalent that holds only `SELECT`/`INSERT` on `events`) — never
//! DDL, never a write to `events`. This mirrors the verifier's own read
//! posture (`crates/hort-server/src/cli/verify_event_chain.rs`) and
//! reuses the same bounded per-stream head shape. The `EventStore` port
//! is **neither used nor widened** — this adapter issues its own bounded
//! `SELECT` that additionally returns the `event_hash` chain column
//! `PersistedEvent` cannot carry, exactly as the verifier does. Reading
//! one more column in this adapter's own query widens no port and
//! changes no trait.
//!
//! ## Consistent cut
//!
//! The head snapshot + `max_global_position` + the `StreamSealed` scan
//! are taken inside one read transaction (`REPEATABLE READ`) so the
//! checkpoint binds a coherent point-in-time; a stream that grew a
//! row between the head read and the
//! global-position read cannot smear the cut.
//!
//! ## `StreamSealed` — a windowed delta, not the history
//!
//! The `DomainEvent::StreamSealed` variant is emitted (ADR 0002 + 0004)
//! to the `StreamId::eventstore_retention()` stream.
//! `sealed_since_previous` therefore carries one `SealedStreamRecord`
//! per seal **past the boundary the caller supplied** — the audit-meta
//! stream position an anchored checkpoint already covered. Empty is a
//! valid, expected result the emitter handles cleanly, and is the steady
//! state: nothing was sealed since the last anchor.
//!
//! The boundary is a `stream_position` on the stream being read, not the
//! `max_global_position` cut, and the difference is load-bearing.
//! `events.global_position` comes from a sequence, so it is assigned in
//! INSERT order and rows become visible in COMMIT order; a seal holding
//! a lower `global_position` than an already-committed neighbour is
//! invisible at the cut, is not carried, and a `global_position >` window
//! past that cut would never read it again — leaving a live seal anchored
//! by no checkpoint, which the verifier reports forever as
//! `AnchorBreak::SealUnanchored`. `UNIQUE (stream_id, stream_position)`
//! is the append path's serializer, so on one stream a visible position
//! implies every lower position is visible: the anchored head is an exact
//! frontier. Read inside the same `REPEATABLE READ` cut as the head
//! query, the windows therefore tile without gaps.
//!
//! The verification half (`PgEventChainReader::read_sealed_records`)
//! issues its own, deliberately **unwindowed** read of this same stream
//! — it justifies a now-absent anchored stream and needs the full seal
//! history permanently. Only this query is windowed.

use sqlx::{PgPool, Row};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{DomainEvent, EventHash, SealedStreamRecord, StreamHead, StreamId};
use hort_domain::ports::event_chain_head_reader::{EventChainHeadReaderPort, LiveChainSnapshot};
use hort_domain::ports::BoxFuture;

/// The never-deleted audit-meta stream id the `StreamSealed` tombstones
/// live on.
///
/// Derives from [`StreamId::eventstore_retention`] — not a hand-pinned
/// literal. The wire form is `admin-<v5-uuid>` (`StreamCategory::Admin`,
/// the deterministic UUIDv5 over the `"eventstore-retention"` label).
/// The verifier verdict logic, chain computation, and
/// `SealedGap`-vs-`Broken` rule are byte-unchanged — only the
/// stream-identity value is derived.
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

/// Translate the caller's anchored audit-meta stream position into the
/// bound the windowed `StreamSealed` read binds.
///
/// `events.stream_position` is a 0-based `bigint`, so `-1` is the
/// "no boundary" value that admits the whole stream — which is what
/// `None` must mean: no checkpoint has anchored this stream, so no seal
/// is anchored yet. `Some(0)` is a real boundary (one event anchored)
/// and stays distinct from it.
///
/// A position wider than `bigint` cannot have come out of the column it
/// is about, so it is an operational invariant breach — surfaced as
/// `Err`, never silently clamped into a window that would skip seals.
pub(crate) fn sealed_position_bound(anchored: Option<u64>) -> DomainResult<i64> {
    match anchored {
        None => Ok(-1),
        Some(position) => i64::try_from(position).map_err(|_| {
            DomainError::Invariant(format!(
                "anchored audit-meta stream position {position} exceeds the \
                 bigint stream_position column it is compared against"
            ))
        }),
    }
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
    fn snapshot_live_chain(
        &self,
        anchored_retention_position: Option<u64>,
    ) -> BoxFuture<'_, DomainResult<LiveChainSnapshot>> {
        Box::pin(async move {
            // Resolve the window bound before opening the cut: a bound
            // that cannot be expressed is this cycle's failure, not a
            // snapshot to take and then throw away.
            let sealed_after = sealed_position_bound(anchored_retention_position)?;

            // One REPEATABLE READ transaction → a consistent cut.
            // All three reads see the same snapshot.
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
            //     bounded shape the verifier uses (DISTINCT ON +
            //     ORDER BY stream_position DESC). The id set is small
            //     (thousands of streams) — one query.
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

            // (3) StreamSealed records on the audit-meta stream (ADR 0004),
            //     windowed past what an anchored checkpoint already
            //     carried. Empty is the steady state (nothing sealed since
            //     the last anchor) and a valid result. Ordered for
            //     determinism.
            //
            //     The window tiles because the bound is a position on this
            //     same stream read in this same cut, and (1) above records
            //     that stream's head for the next run's bound: a seal this
            //     query cannot see sits above the head it records. Deriving
            //     the bound from `max_global_position` instead would not
            //     tile — see the module doc.
            let sealed_rows = sqlx::query(
                r#"SELECT event_data
                   FROM events
                   WHERE stream_id = $1 AND event_type = 'StreamSealed'
                     AND stream_position > $2
                   ORDER BY stream_position ASC"#,
            )
            .bind(retention_stream_id())
            .bind(sealed_after)
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
    use hort_domain::ports::event_store::EventStore;
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
    fn no_boundary_admits_the_whole_stream() {
        // `stream_position` is 0-based, so the sentinel has to sit below
        // every real position: with no checkpoint anchoring the
        // audit-meta stream no seal is anchored, and the next checkpoint
        // must carry all of them.
        assert_eq!(sealed_position_bound(None).unwrap(), -1);
    }

    #[test]
    fn position_zero_is_a_boundary_not_an_absence() {
        // The distinction the sentinel exists for: `Some(0)` windows out
        // the seal at position 0, `None` keeps it.
        assert_eq!(sealed_position_bound(Some(0)).unwrap(), 0);
        assert_ne!(
            sealed_position_bound(Some(0)).unwrap(),
            sealed_position_bound(None).unwrap()
        );
    }

    #[test]
    fn a_real_boundary_passes_through_unchanged() {
        assert_eq!(sealed_position_bound(Some(41)).unwrap(), 41);
        assert_eq!(
            sealed_position_bound(Some(i64::MAX as u64)).unwrap(),
            i64::MAX
        );
    }

    #[test]
    fn a_boundary_wider_than_bigint_is_an_invariant_breach() {
        // Unreachable from a position that came out of the column, so it
        // is a breach rather than a clamp: clamping down would re-anchor
        // the history and clamping up would window seals away for good.
        let e = sealed_position_bound(Some(u64::MAX)).unwrap_err();
        assert!(
            e.to_string().contains("exceeds the"),
            "unexpected message: {e}"
        );
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
    // Mirrors the `maybe_pool()` early-return idiom used by the verifier
    // (`crates/hort-server/src/cli/verify_event_chain.rs`): no DATABASE_URL
    // ⇒ silent early return so `cargo test --workspace --lib` stays
    // green locally; Tier-2/CI sets DATABASE_URL and the body runs.

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;
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
        let snap = reader.snapshot_live_chain(None).await.unwrap();
        assert!(snap.max_global_position >= snap.heads.len() as u64 || snap.heads.is_empty());
        // `sealed_since_previous` is NOT empty in a shared DB that has
        // had sealing activity. The invariant that still always holds: every record the
        // adapter returned parsed cleanly into a well-formed
        // `SealedStreamRecord` (non-empty `sealed_stream_id`) — the
        // StreamSealed read+parse path is exercised whether the stream
        // is empty or sibling-populated.
        assert!(snap
            .sealed_since_previous
            .iter()
            .all(|r| !r.sealed_stream_id.is_empty()));
    }

    /// The window is real SQL, so assert it against real rows: seal two
    /// streams through the production `delete_stream` path, then read the
    /// audit-meta stream at each boundary the emission cycle could hand
    /// this adapter.
    ///
    /// Asserts on the two tombstones this test created rather than on the
    /// whole set, so it states the window and not the database's
    /// emptiness.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_sealed_read_is_windowed_on_the_boundary_it_is_handed() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let store = crate::event_store::PgEventStore::new(pool.clone())
            .await
            .unwrap();
        let reader = PgEventChainHeadReader::new(pool.clone());

        // Two seals through the real tombstone path, so the audit-meta
        // rows are exactly what production writes.
        let first_id = seal_one_stream(&store, 0).await;
        let second_id = seal_one_stream(&store, 1).await;

        // The audit-meta positions those two tombstones landed at.
        let positions: Vec<i64> = sqlx::query_scalar(
            r#"SELECT stream_position FROM events
               WHERE stream_id = $1 AND event_type = 'StreamSealed'
               ORDER BY stream_position ASC"#,
        )
        .bind(retention_stream_id())
        .fetch_all(&pool)
        .await
        .unwrap();
        let (first_pos, second_pos) = match positions[..] {
            [.., a, b] => (a as u64, b as u64),
            _ => panic!("both tombstones must be on the audit-meta stream"),
        };
        assert!(first_pos < second_pos, "the tombstones must be ordered");

        let carried = |b: Option<u64>| {
            let reader = &reader;
            async move {
                reader
                    .snapshot_live_chain(b)
                    .await
                    .unwrap()
                    .sealed_since_previous
                    .iter()
                    .map(|r| r.sealed_stream_id.clone())
                    .collect::<Vec<_>>()
            }
        };

        // No boundary ⇒ both (the first-checkpoint case).
        let all = carried(None).await;
        assert!(all.contains(&first_id) && all.contains(&second_id));

        // Boundary at the first tombstone ⇒ only the second survives.
        let after_first = carried(Some(first_pos)).await;
        assert!(
            !after_first.contains(&first_id),
            "a seal at or below the boundary must be windowed out"
        );
        assert!(
            after_first.contains(&second_id),
            "a seal past the boundary must still be carried"
        );

        // Boundary at the second ⇒ neither: the steady state in which
        // nothing was sealed since the last anchor.
        let after_second = carried(Some(second_pos)).await;
        assert!(!after_second.contains(&first_id) && !after_second.contains(&second_id));

        // The boundary the NEXT cycle derives is this snapshot's own
        // audit-meta head, and it must cover every seal this cut returned
        // — the property that makes the windows tile. A head below it
        // would re-anchor; a head above it would window a seal away for
        // good.
        let head = reader
            .snapshot_live_chain(Some(second_pos))
            .await
            .unwrap()
            .heads
            .into_iter()
            .find(|h| h.stream_id == retention_stream_id())
            .expect("the audit-meta stream is live and never deleted");
        assert!(head.final_stream_position >= second_pos);
    }

    /// Append one event to a fresh artifact stream and seal it through
    /// `delete_stream`, returning the sealed stream's wire id. A
    /// single-event fresh stream has head `stream_position` 0, so the
    /// seal authority needs no tail query.
    async fn seal_one_stream(store: &crate::event_store::PgEventStore, marker: u8) -> String {
        use hort_domain::events::{system_actor, ArtifactIngested, IngestSource};
        use hort_domain::ports::event_store::{
            AppendEvents, EventToAppend, ExpectedVersion, SealAuthority,
        };

        let artifact_id = Uuid::new_v4();
        let stream = StreamId::artifact(artifact_id);
        store
            .append(AppendEvents {
                stream_id: stream.clone(),
                expected_version: ExpectedVersion::NoStream,
                events: vec![EventToAppend::new(DomainEvent::ArtifactIngested(
                    ArtifactIngested {
                        artifact_id,
                        repository_id: Uuid::new_v4(),
                        name: format!("seal-window-{marker}"),
                        version: Some("1.0.0".into()),
                        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            .parse()
                            .unwrap(),
                        size_bytes: 10,
                        source: IngestSource::Direct,
                        metadata: serde_json::Value::Null,
                        metadata_blob: None,
                        upstream_published_at: None,
                    },
                ))],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: system_actor(),
            })
            .await
            .unwrap();
        store
            .delete_stream(
                stream.clone(),
                SealAuthority {
                    final_stream_position: 0,
                },
            )
            .await
            .unwrap();
        stream.to_string()
    }
}
