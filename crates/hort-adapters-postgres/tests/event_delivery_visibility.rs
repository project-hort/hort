//! What the broadcast channel and a `global_position` cursor can and
//! cannot tell a notification subscriber.
//!
//! Each test states a property of the *store*, which is what the
//! dispatcher's delivery loop reads
//! (`hort-app::dispatcher::subscription_task`). Each needs a live
//! PostgreSQL; without `DATABASE_URL` they early-return, matching the
//! convention in `event_store.rs`. Each takes a throwaway database via
//! `isolated_db_from` and carries the crate-wide `#[serial(hort_pg_db)]`
//! key: a per-test database is not isolation from the cluster-global
//! work the migration set and the stale-database sweeper do.
//!
//! 1. `transactional_append_is_absent_from_the_broadcast_channel` —
//!    events written through a lifecycle port land in the store and
//!    **not** on the publisher's channel. This is the layering rule
//!    (`hort-adapters-postgres` holds no broadcast sender; the
//!    application-layer `EventStorePublisher` is the only sender) seen
//!    from the outside, and it is why delivery is driven by reads of the
//!    store rather than by the channel.
//! 2. `a_later_committing_transaction_can_hold_a_lower_global_position`
//!    — `events.global_position` defaults to `nextval`, evaluated at
//!    INSERT, while a row becomes visible at COMMIT. The two orders can
//!    disagree, so a reader that treats the highest position it has seen
//!    as a floor can step over a row that is still in flight. Pinned
//!    because every consumer of the event log checkpoints on
//!    `global_position` — the dispatcher's `last_delivered_position` and
//!    the `GET /api/v1/events` `next_after` alike — and the property
//!    bounds what any of them can promise.
//! 3. `an_xmin_horizon_does_not_close_the_late_commit_race` — the
//!    obvious reader-side answer to (2) is a visibility horizon: return
//!    only rows whose inserting transaction is already below
//!    `pg_snapshot_xmin(pg_current_snapshot())`, so a cursor cannot pass
//!    a row that was still in flight. It does not hold, because the
//!    `nextval` order and the xid-assignment order are independent, and
//!    several transactional write paths take their xid *before* they
//!    draw a position. Pinned so a later reader does not adopt the
//!    horizon on sight.
//!
//! (2) and (3) pin **accepted behaviour**, not an open defect. ADR 0061
//! takes the decision: the late-commit gap is accepted and documented,
//! because the naive horizon is unsound (3) and the sound sampled one
//! trades a bounded partial loss for an unbounded delivery stall. A
//! change that turns either red is a change to the position model, which
//! re-opens that decision rather than discharging it.

use std::env;
use std::sync::Arc;

use chrono::Utc;
use hort_adapters_postgres::artifact_lifecycle::PgArtifactLifecycle;
use hort_adapters_postgres::artifact_metadata_repo::PgArtifactMetadataRepository;
use hort_adapters_postgres::artifact_repo::PgArtifactRepository;
use hort_adapters_postgres::event_store::PgEventStore;
use hort_app::event_store_publisher::EventStorePublisher;
use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::events::{
    system_actor, ArtifactIngested, AuthenticationAttempted, DomainEvent, IngestSource,
    StreamCategory, StreamId,
};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::event_store::{
    AppendEvents, EventStore, EventToAppend, ExpectedVersion, SubscribeFrom,
};
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-delivery-{}", id.simple());
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $3, 'pypi'::repository_format, 'hosted'::repository_type,
               'filesystem', $4, 'local_only'::replication_priority
           )"#,
    )
    .bind(id)
    .bind(&key)
    .bind(&key)
    .bind(format!("/tmp/{key}"))
    .execute(pool)
    .await
    .expect("seed repo");
    id
}

fn artifact(repo_id: Uuid) -> Artifact {
    let id = Uuid::new_v4();
    // Two 32-hex uuid halves → a valid 64-lowercase-hex SHA-256 string.
    let sha = id.simple().to_string().repeat(2);
    Artifact {
        id,
        repository_id: repo_id,
        name: "delivery-probe".into(),
        name_as_published: "delivery-probe".into(),
        version: Some("1.0.0".into()),
        path: format!("simple/delivery-probe/{}.tar.gz", id.simple()),
        size_bytes: 7,
        sha256_checksum: sha.parse().expect("valid sha256"),
        sha1_checksum: None,
        md5_checksum: None,
        content_type: "application/octet-stream".into(),
        quarantine_status: QuarantineStatus::Quarantined,
        rejection_reason: None,
        quarantine_window_start: None,
        quarantine_deadline: None,
        provenance_hold_indefinite: false,
        deleted_at: None,
        upstream_published_at: None,
        uploaded_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn auth_batch() -> AppendEvents {
    AppendEvents {
        stream_id: StreamId::auth_attempts(Utc::now().date_naive()),
        expected_version: ExpectedVersion::Any,
        events: vec![EventToAppend::new(DomainEvent::AuthenticationAttempted(
            AuthenticationAttempted {
                client_ip: "127.0.0.1".parse().expect("literal ip"),
                result: "local_invalid_credentials".into(),
                external_id_if_decoded: None,
                at: Utc::now(),
            },
        ))],
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: system_actor(),
    }
}

/// One `auth`-category event INSERT with exactly the columns
/// `append_with_conn` binds, `global_position` left to its `nextval`
/// DEFAULT. Raw SQL because the tests below hold two appends open across
/// each other, which the adapter's own `append` (one transaction per
/// call) cannot do and which `append_in_tx` is crate-internal for.
const RAW_AUTH_EVENT_INSERT: &str = r#"
    INSERT INTO events (
        event_id, stream_id, stream_category, stream_position,
        event_type, event_version, event_data, correlation_id,
        actor_type, prev_event_hash, event_hash
    )
    VALUES ($1, $2, 'auth', $3, 'AuthenticationAttempted', 1, $4::jsonb,
            $5, 'system', $6, $6)
    RETURNING global_position"#;

/// Append one raw event on an open transaction and return its
/// `global_position`. The chain hashes are a 32-byte placeholder: these
/// tests are about positions and visibility, not the chain, and the
/// `octet_length = 32` CHECK is all the column enforces here.
async fn raw_append(tx: &mut sqlx::PgConnection, stream_id: &str, stream_position: i64) -> i64 {
    let payload = serde_json::json!({
        "type": "AuthenticationAttempted",
        "data": {
            "client_ip": "127.0.0.1",
            "result": "local_invalid_credentials",
            "external_id_if_decoded": null,
            "at": Utc::now(),
        }
    });
    sqlx::query_scalar(RAW_AUTH_EVENT_INSERT)
        .bind(Uuid::new_v4())
        .bind(stream_id)
        .bind(stream_position)
        .bind(&payload)
        .bind(Uuid::new_v4())
        .bind(vec![0u8; 32])
        .fetch_one(tx)
        .await
        .expect("raw event insert")
}

/// A lifecycle-port append reaches the store and not the channel; a
/// port append through the publisher reaches both. The asymmetry is
/// structural — the adapter has no sender to call — so a subscriber
/// that listened only to the channel would never see the artifact
/// lifecycle at all.
#[tokio::test]
#[serial(hort_pg_db)]
async fn transactional_append_is_absent_from_the_broadcast_channel() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let event_store = Arc::new(PgEventStore::new(pool.clone()).await.expect("event store"));
    let lifecycle = PgArtifactLifecycle::new(
        event_store.clone(),
        Arc::new(PgArtifactRepository::new(pool.clone(), event_store.clone())),
        Arc::new(PgArtifactMetadataRepository::new(pool.clone())),
    );

    let (sender, mut rx) = tokio::sync::broadcast::channel(64);
    let publisher = EventStorePublisher::new(event_store.clone(), sender);

    // Control: the port append the publisher wraps does reach the channel.
    publisher.append(auth_batch()).await.expect("append");
    assert!(
        rx.try_recv().is_ok(),
        "the publisher must broadcast what it appends — otherwise this \
         test proves nothing about the transactional path"
    );

    let artifact = artifact(repo_id);
    let batch = AppendEvents {
        stream_id: StreamId::artifact(artifact.id),
        expected_version: ExpectedVersion::NoStream,
        events: vec![EventToAppend::new(DomainEvent::ArtifactIngested(
            ArtifactIngested {
                artifact_id: artifact.id,
                repository_id: repo_id,
                name: artifact.name.clone(),
                version: artifact.version.clone(),
                sha256: artifact.sha256_checksum.clone(),
                size_bytes: artifact.size_bytes,
                source: IngestSource::Proxied,
                metadata: serde_json::Value::Null,
                metadata_blob: None,
                upstream_published_at: None,
            },
        ))],
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: system_actor(),
    };
    lifecycle
        .commit_transition(&artifact, batch, None)
        .await
        .expect("commit_transition");

    assert!(
        matches!(
            rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ),
        "a transactional append must not reach the channel: the adapter \
         holds no sender, and putting one there would invert the \
         dependency the publisher exists to express"
    );

    let stored = event_store
        .read_category(StreamCategory::Artifact, SubscribeFrom::Start, 100)
        .await
        .expect("read_category");
    assert_eq!(
        stored.len(),
        1,
        "the event is durably in the store — reading it is what delivers it"
    );
}

/// `global_position` orders INSERTs, not COMMITs. A reader that has
/// already passed position N cannot be promised it saw everything below
/// N, because a transaction holding a lower position may still commit.
///
/// Accepted behaviour under ADR 0061, which decides to state this gap
/// honestly rather than close it: the cursor stays a bare high-water
/// mark, `global_position` and `next_after` keep their meaning, and a
/// consumer that needs completeness detects the loss instead — per-stream
/// `stream_position` contiguity, or a re-read of a trailing window. So
/// what this test pins is the promise the log makes, and a change that
/// turns it red re-opens that decision.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_later_committing_transaction_can_hold_a_lower_global_position() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let event_store = PgEventStore::new(pool.clone()).await.expect("event store");
    let stream_id = StreamId::auth_attempts(Utc::now().date_naive()).to_string();

    // Raw INSERTs rather than the adapter's `append`: `append` opens and
    // commits its own transaction, so two appends cannot be held open
    // across each other through it, and `append_in_tx` — which can — is
    // crate-internal. `RAW_AUTH_EVENT_INSERT` carries the columns
    // `append_with_conn` binds.
    let mut slow = pool.begin().await.expect("begin slow");
    let slow_position = raw_append(&mut slow, &stream_id, 0).await;

    let mut quick = pool.begin().await.expect("begin quick");
    let quick_position = raw_append(&mut quick, &stream_id, 1).await;
    quick.commit().await.expect("commit quick");

    assert!(
        slow_position < quick_position,
        "the still-open transaction took the lower sequence value"
    );

    let visible = event_store
        .read_category(StreamCategory::AuthAttempts, SubscribeFrom::Start, 100)
        .await
        .expect("read while the slow transaction is open");
    let positions: Vec<u64> = visible.iter().map(|e| e.global_position).collect();
    assert_eq!(
        positions,
        vec![quick_position as u64],
        "only the committed row is visible, and it is the higher position"
    );

    slow.commit().await.expect("commit slow");

    let after = event_store
        .read_category(
            StreamCategory::AuthAttempts,
            SubscribeFrom::AfterGlobal(quick_position as u64),
            100,
        )
        .await
        .expect("read from the position the reader had reached");
    assert!(
        !after
            .iter()
            .any(|e| e.global_position == slow_position as u64),
        "a reader that advanced to {quick_position} never sees \
         {slow_position} again: a bare high-water-mark cursor cannot \
         promise completeness over a sequence taken at INSERT"
    );
}

/// An `xmin` visibility horizon does not close the race the test above
/// pins, and this states why in the shape the codebase actually writes in.
///
/// This is the evidence behind a decision rather than a report of an open
/// defect: ADR 0061 rejects the horizon on the strength of what is
/// asserted below, and accepts the race it fails to close. A change that
/// turns this test red re-opens that rejection — it does not license
/// adopting the horizon.
///
/// The horizon is the obvious reader-side fix: return only rows whose
/// inserting transaction is below `pg_snapshot_xmin(pg_current_snapshot())`
/// — i.e. rows whose transaction has already finished — so a cursor can
/// never advance past a position that was still in flight. That reasoning
/// needs the two orders to agree: it bounds *positions* by reasoning about
/// *transaction ids*, and it is sound only if a lower position implies a
/// lower-or-equal xid.
///
/// The two orders are independent. A position is drawn by `nextval` when
/// the events INSERT executes; an xid is assigned by the transaction's
/// first write. So a transaction that writes its projection row *before*
/// it appends holds a low xid and draws a high position, and it is exactly
/// that shape the adapter ships in: `ref_lifecycle::move_ref` (a
/// `SELECT … FOR UPDATE` plus an `UPDATE mutable_refs`, then the append),
/// `ref_lifecycle::retire_ref`, `artifact_group_lifecycle::{commit_member_added,
/// commit_member_removed}` and `purge_gc::complete_artifact_purge` all
/// write first and append last, while `artifact_lifecycle::commit_transition`
/// appends first. Race the two and the committed row carries the *lower*
/// xid and the *higher* position: it is below the horizon while the lower
/// position is above it, so the horizon reader advances over the gap
/// exactly as the bare high-water mark does.
///
/// This is not a specification of PostgreSQL's internals. What it pins is
/// that the horizon cannot be assumed to cover the race — if a future
/// server made xid assignment precede default evaluation and turned this
/// red, the conclusion to re-derive is what the horizon covers *then*, not
/// that it now covers everything: the converse window (a position drawn
/// before the inserting transaction has an xid at all) closes only if the
/// two steps become one atomic step, which nothing promises.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_xmin_horizon_does_not_close_the_late_commit_race() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool).await;
    let event_store = PgEventStore::new(pool.clone()).await.expect("event store");
    let stream_id = StreamId::auth_attempts(Utc::now().date_naive()).to_string();

    // The append-last writer: its projection row goes in first, which is
    // what assigns its xid — the order `ref_lifecycle::move_ref` and
    // `artifact_group_lifecycle::commit_member_added` both write in.
    let mut append_last = pool.begin().await.expect("begin append-last");
    sqlx::query(
        r#"INSERT INTO mutable_refs (
               id, repository_id, namespace, ref_name, target_kind, target_version
           ) VALUES ($1, $2, 'library', $3, 'version', '1.0.0')"#,
    )
    .bind(Uuid::new_v4())
    .bind(repo_id)
    .bind(format!("ref-{}", Uuid::new_v4().simple()))
    .execute(&mut *append_last)
    .await
    .expect("projection write");
    let xid_append_last: Option<i64> =
        sqlx::query_scalar("SELECT pg_current_xact_id_if_assigned()::text::bigint")
            .fetch_one(&mut *append_last)
            .await
            .expect("xid probe");
    let xid_append_last = xid_append_last.expect(
        "the projection write assigns the transaction id, before this transaction \
         has drawn any global_position — that is the whole premise",
    );

    // The append-first writer: its xid comes from the events INSERT
    // itself, so it is assigned *after* the one above and its position is
    // drawn *before*.
    let mut append_first = pool.begin().await.expect("begin append-first");
    let position_append_first = raw_append(&mut append_first, &stream_id, 0).await;
    let xid_append_first: i64 =
        sqlx::query_scalar("SELECT pg_current_xact_id_if_assigned()::text::bigint")
            .fetch_one(&mut *append_first)
            .await
            .expect("xid probe");

    let position_append_last = raw_append(&mut append_last, &stream_id, 1).await;
    append_last.commit().await.expect("commit append-last");

    assert!(
        position_append_first < position_append_last,
        "the still-open transaction drew the lower position \
         ({position_append_first} vs {position_append_last})"
    );
    assert!(
        xid_append_first > xid_append_last,
        "and the committed transaction holds the LOWER xid ({xid_append_last}) \
         than the still-open one ({xid_append_first}): the position order and the \
         xid order disagree, which is what the horizon cannot survive"
    );

    // The horizon read: the same category read plus "only settled rows".
    // The `::text::bigint` casts compare a 32-bit row `xmin` with a 64-bit
    // snapshot xid and so ignore xid epoch — fine on a freshly created
    // database, and one more cost of this shape rather than a detail.
    let horizon_read = r#"
        SELECT global_position
          FROM events
         WHERE stream_category = 'auth'
           AND global_position > $1
           AND xmin::text::bigint
               < pg_snapshot_xmin(pg_current_snapshot())::text::bigint
         ORDER BY global_position
         LIMIT 100"#;
    let settled: Vec<i64> = sqlx::query_scalar(horizon_read)
        .bind(0_i64)
        .fetch_all(&pool)
        .await
        .expect("horizon read while the append-first transaction is open");
    assert_eq!(
        settled,
        vec![position_append_last],
        "the horizon returns the committed row — it is below the horizon because \
         its xid is lower — and a reader that returns it advances its cursor to \
         {position_append_last}, over the still-open {position_append_first}"
    );

    append_first.commit().await.expect("commit append-first");

    let after_horizon: Vec<i64> = sqlx::query_scalar(horizon_read)
        .bind(position_append_last)
        .fetch_all(&pool)
        .await
        .expect("horizon read from the position the reader had reached");
    assert!(
        !after_horizon.contains(&position_append_first),
        "a horizon reader that advanced to {position_append_last} never sees \
         {position_append_first} either: an xmin horizon bounds positions by \
         reasoning about transaction ids, and the two orders are independent"
    );

    // Same for the shipped read, which is what the dispatcher and
    // `GET /api/v1/events` actually call — stated here so the two are
    // compared on one page rather than across two tests.
    let after_plain = event_store
        .read_category(
            StreamCategory::AuthAttempts,
            SubscribeFrom::AfterGlobal(position_append_last as u64),
            100,
        )
        .await
        .expect("read_category from the position the reader had reached");
    assert!(
        !after_plain
            .iter()
            .any(|e| e.global_position == position_append_first as u64),
        "and the shipped bare-mark read does not see it either"
    );
}
