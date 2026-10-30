//! `PgArtifactLifecycle` commit-contract integration tests (ADR 0002/0004).
//!
//! Two halves of the same contract, against a real database:
//!
//! **Atomicity (no-strand).** `commit_transition_with_enqueues` must commit
//! the transition events, the artifact projection, and the ingest-time `jobs`
//! rows in ONE transaction, so a failed enqueue can never leave an artifact
//! ingested with a `ScanRequested` event but no `jobs` row (the dual-write
//! strand the method was added to close).
//!
//! **Agreement.** Atomicity alone is not enough: a pair whose `AppendEvents`
//! is not the handed-in artifact's stream would commit *atomically*, leaving
//! the `artifacts` row and the stream it is derived from permanently
//! contradicting each other with no intermediate state for anything to
//! notice. Such a pair must not commit at all.
//!
//! Force-failure vector: an invalid `trigger_source` violates the
//! `jobs.trigger_source` CHECK (migration 009), so the in-tx scan insert
//! errors — the whole transition must then roll back.
//!
//! `DATABASE_URL`-gated; self-skips on hosts without a database (suite
//! convention). Uses `isolated_db_from` (a per-test throwaway database),
//! which isolates the rows but not the server: creating and migrating
//! that database is cluster-global work (`CREATE DATABASE`, the
//! migration set's `CREATE ROLE`, the shared catalogs the stale-database
//! sweeper walks), so each test also carries the workspace-wide
//! `#[serial(hort_pg_db)]` key.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test ingest_enqueue_atomicity
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;

use chrono::Utc;
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::artifact_lifecycle::PgArtifactLifecycle;
use hort_adapters_postgres::artifact_metadata_repo::PgArtifactMetadataRepository;
use hort_adapters_postgres::artifact_repo::PgArtifactRepository;
use hort_adapters_postgres::event_store::PgEventStore;
use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::events::{
    system_actor, ArtifactIngested, DomainEvent, IngestSource, ScanRequested, StreamId,
};
use hort_domain::ports::artifact_lifecycle::{ArtifactLifecyclePort, IngestEnqueue};
use hort_domain::ports::event_store::{AppendEvents, EventToAppend, ExpectedVersion};

async fn maybe_setup() -> Option<(PgPool, Uuid)> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    let repo_id = seed_repo(&pool).await;
    Some((pool, repo_id))
}

async fn lifecycle(pool: &PgPool) -> PgArtifactLifecycle {
    let event_store = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .expect("event store init"),
    );
    let artifact_repo = Arc::new(PgArtifactRepository::new(pool.clone(), event_store.clone()));
    let metadata_repo = Arc::new(PgArtifactMetadataRepository::new(pool.clone()));
    PgArtifactLifecycle::new(event_store, artifact_repo, metadata_repo)
}

async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-enqatomic-{}", id.simple());
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
    // Two 32-hex uuid halves → a valid 64-lowercase-hex SHA-256 string,
    // unique per artifact. NB: `format!("{:0<64}", id.simple())` does NOT
    // work — `uuid::Simple`'s `Display` ignores the width/fill flags, so it
    // stays 32 chars and `ContentHash::parse` rejects it.
    let sha = id.simple().to_string().repeat(2);
    Artifact {
        id,
        repository_id: repo_id,
        name: "enq-atomic".into(),
        name_as_published: "enq-atomic".into(),
        version: Some("1.0.0".into()),
        path: format!("simple/enq-atomic/{}.tar.gz", id.simple()),
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

fn ingest_events(a: &Artifact) -> AppendEvents {
    AppendEvents {
        stream_id: StreamId::artifact(a.id),
        expected_version: ExpectedVersion::NoStream,
        events: vec![
            EventToAppend {
                event_id: Uuid::new_v4(),
                event: DomainEvent::ArtifactIngested(ArtifactIngested {
                    artifact_id: a.id,
                    repository_id: a.repository_id,
                    name: a.name.clone(),
                    version: a.version.clone(),
                    sha256: a.sha256_checksum.clone(),
                    size_bytes: a.size_bytes,
                    source: IngestSource::Proxied,
                    metadata: serde_json::Value::Null,
                    metadata_blob: None,
                    upstream_published_at: None,
                }),
            },
            EventToAppend {
                event_id: Uuid::new_v4(),
                event: DomainEvent::ScanRequested(ScanRequested {
                    artifact_id: a.id,
                    scanner: "default".into(),
                }),
            },
        ],
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: system_actor(),
    }
}

/// Rows on one stream, by its wire-form id — `count` binds a `Uuid`, and
/// a stream id is text.
async fn stream_rows(pool: &PgPool, stream_id: &str) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM public.events WHERE stream_id = $1")
        .bind(stream_id)
        .fetch_one(pool)
        .await
        .expect("count events on stream")
}

async fn count(pool: &PgPool, sql: &'static str, id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>(sql)
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count query")
}

/// No-strand: a failed in-tx enqueue (invalid `trigger_source` → the
/// `jobs.trigger_source` CHECK fires) rolls back the WHOLE transition — no
/// artifact row and no jobs row survive. The artifact is never
/// ingested-but-stranded.
#[tokio::test]
#[serial(hort_pg_db)]
async fn enqueue_failure_rolls_back_transition_no_strand() {
    let Some((pool, repo_id)) = maybe_setup().await else {
        return;
    };
    let lc = lifecycle(&pool).await;
    let a = artifact(repo_id);

    let result = lc
        .commit_transition_with_enqueues(
            &a,
            ingest_events(&a),
            None,
            &[IngestEnqueue::Scan {
                format: "pypi".into(),
                priority: 0,
                // Not in the migration-009 trigger_source CHECK set → the
                // in-tx scan insert errors, which must abort the transition.
                trigger_source: "bogus-not-in-check".into(),
            }],
            &[],
        )
        .await;
    assert!(
        result.is_err(),
        "an invalid enqueue must fail the commit, not silently drop the job"
    );

    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.artifacts WHERE id = $1",
            a.id
        )
        .await,
        0,
        "the artifact save must roll back with the failed enqueue (no event-without-job strand)",
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.jobs WHERE artifact_id = $1",
            a.id
        )
        .await,
        0,
        "no jobs row may survive the rolled-back transition",
    );
}

/// Happy path: the scan and provenance-verify enqueues land atomically with
/// the artifact projection in one transaction.
#[tokio::test]
#[serial(hort_pg_db)]
async fn commit_lands_artifact_and_scan_and_provenance_jobs() {
    let Some((pool, repo_id)) = maybe_setup().await else {
        return;
    };
    let lc = lifecycle(&pool).await;
    let a = artifact(repo_id);

    lc.commit_transition_with_enqueues(
        &a,
        ingest_events(&a),
        None,
        &[
            IngestEnqueue::Scan {
                format: "pypi".into(),
                priority: 0,
                trigger_source: "ingest".into(),
            },
            IngestEnqueue::ProvenanceVerify {
                priority: 0,
                trigger_source: "ingest".into(),
            },
        ],
        &[],
    )
    .await
    .expect("a valid commit must succeed");

    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.artifacts WHERE id = $1",
            a.id
        )
        .await,
        1,
        "the artifact is committed",
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.jobs WHERE artifact_id = $1 AND kind = 'scan'",
            a.id
        )
        .await,
        1,
        "the scan job is committed atomically with the transition",
    );
    let prov = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM public.jobs \
         WHERE kind = 'provenance-verify' AND params->>'artifact_id' = $1",
    )
    .bind(a.id.to_string())
    .fetch_one(&pool)
    .await
    .expect("provenance count query");
    assert_eq!(
        prov, 1,
        "the provenance-verify job is committed atomically with the transition",
    );
}

/// A batch on another artifact's stream does not commit: no event row on
/// the foreign stream, no artifact row, nothing.
///
/// The transaction is the hazard here rather than the protection — both
/// halves would land together and stay landed. The refusal is therefore
/// before the connection is opened, not a rollback after it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn commit_transition_refuses_a_batch_on_another_artifacts_stream() {
    let Some((pool, repo_id)) = maybe_setup().await else {
        return;
    };
    let lc = lifecycle(&pool).await;
    let a = artifact(repo_id);
    let other = Uuid::new_v4();

    let mut events = ingest_events(&a);
    events.stream_id = StreamId::artifact(other);
    let foreign_stream = events.stream_id.to_string();

    let err = lc
        .commit_transition(&a, events, None)
        .await
        .expect_err("a pair naming two different artifacts must not commit");
    assert!(
        err.to_string().contains(&a.id.to_string()) && err.to_string().contains(&other.to_string()),
        "the refusal must name both sides: {err}"
    );

    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.artifacts WHERE id = $1",
            a.id
        )
        .await,
        0,
        "no artifact row may survive a refused pair",
    );
    assert_eq!(
        stream_rows(&pool, &foreign_stream).await,
        0,
        "no event may land on the stream the batch wrongly named",
    );
}

/// Same rule on the ingest path, which carries the enqueues and the
/// content-reference edges too — none of them may land either.
#[tokio::test]
#[serial(hort_pg_db)]
async fn commit_transition_with_enqueues_refuses_a_batch_on_another_artifacts_stream() {
    let Some((pool, repo_id)) = maybe_setup().await else {
        return;
    };
    let lc = lifecycle(&pool).await;
    let a = artifact(repo_id);
    let other = Uuid::new_v4();

    let mut events = ingest_events(&a);
    events.stream_id = StreamId::artifact(other);
    let foreign_stream = events.stream_id.to_string();

    lc.commit_transition_with_enqueues(
        &a,
        events,
        None,
        &[IngestEnqueue::Scan {
            format: "pypi".into(),
            priority: 0,
            trigger_source: "ingest".into(),
        }],
        &[],
    )
    .await
    .expect_err("a pair naming two different artifacts must not commit");

    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.artifacts WHERE id = $1",
            a.id
        )
        .await,
        0,
        "no artifact row may survive a refused pair",
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.jobs WHERE artifact_id = $1",
            a.id
        )
        .await,
        0,
        "no jobs row may survive a refused pair",
    );
    assert_eq!(
        stream_rows(&pool, &foreign_stream).await,
        0,
        "no event may land on the stream the batch wrongly named",
    );
}

/// And the verdict path, which writes only the status column — the same
/// refusal, in the method whose projection write is the narrowest.
#[tokio::test]
#[serial(hort_pg_db)]
async fn commit_provenance_verdict_refuses_a_batch_on_another_artifacts_stream() {
    let Some((pool, repo_id)) = maybe_setup().await else {
        return;
    };
    let lc = lifecycle(&pool).await;
    let a = artifact(repo_id);
    let other = Uuid::new_v4();

    let mut events = ingest_events(&a);
    events.stream_id = StreamId::artifact(other);
    let foreign_stream = events.stream_id.to_string();

    lc.commit_provenance_verdict(&a, events, QuarantineStatus::Quarantined)
        .await
        .expect_err("a pair naming two different artifacts must not commit");

    assert_eq!(
        stream_rows(&pool, &foreign_stream).await,
        0,
        "no event may land on the stream the batch wrongly named",
    );
}

/// COUNTER-TEST: the matching pair commits unchanged. Both halves land,
/// on the artifact's own stream — so the rule above refuses the
/// mismatch and nothing else.
#[tokio::test]
#[serial(hort_pg_db)]
async fn commit_transition_commits_a_matching_pair_unchanged() {
    let Some((pool, repo_id)) = maybe_setup().await else {
        return;
    };
    let lc = lifecycle(&pool).await;
    let a = artifact(repo_id);
    let own_stream = StreamId::artifact(a.id).to_string();

    lc.commit_transition(&a, ingest_events(&a), None)
        .await
        .expect("a matching pair commits");

    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.artifacts WHERE id = $1",
            a.id
        )
        .await,
        1,
        "the artifact row lands",
    );
    assert_eq!(
        stream_rows(&pool, &own_stream).await,
        2,
        "both events land on the artifact's own stream",
    );
}
