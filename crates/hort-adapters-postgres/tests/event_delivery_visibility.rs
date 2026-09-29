//! What the broadcast channel and a `global_position` cursor can and
//! cannot tell a notification subscriber.
//!
//! Both tests state a property of the *store*, which is what the
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
    // crate-internal. The columns below are exactly what
    // `append_with_conn` binds.
    let chain_placeholder = vec![0u8; 32];
    let insert = r#"
        INSERT INTO events (
            event_id, stream_id, stream_category, stream_position,
            event_type, event_version, event_data, correlation_id,
            actor_type, prev_event_hash, event_hash
        )
        VALUES ($1, $2, 'auth', $3, 'AuthenticationAttempted', 1, $4::jsonb,
                $5, 'system', $6, $7)
        RETURNING global_position"#;
    let payload = serde_json::json!({
        "type": "AuthenticationAttempted",
        "data": {
            "client_ip": "127.0.0.1",
            "result": "local_invalid_credentials",
            "external_id_if_decoded": null,
            "at": Utc::now(),
        }
    });

    let mut slow = pool.begin().await.expect("begin slow");
    let slow_position: i64 = sqlx::query_scalar(insert)
        .bind(Uuid::new_v4())
        .bind(&stream_id)
        .bind(0_i64)
        .bind(&payload)
        .bind(Uuid::new_v4())
        .bind(&chain_placeholder)
        .bind(&chain_placeholder)
        .fetch_one(&mut *slow)
        .await
        .expect("insert in the slow transaction");

    let mut quick = pool.begin().await.expect("begin quick");
    let quick_position: i64 = sqlx::query_scalar(insert)
        .bind(Uuid::new_v4())
        .bind(&stream_id)
        .bind(1_i64)
        .bind(&payload)
        .bind(Uuid::new_v4())
        .bind(&chain_placeholder)
        .bind(&chain_placeholder)
        .fetch_one(&mut *quick)
        .await
        .expect("insert in the quick transaction");
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
