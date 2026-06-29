//! Ingest-enqueue atomicity integration tests (ADR 0002/0004 no-strand).
//!
//! `PgArtifactLifecycle::commit_transition_with_enqueues` must commit the
//! transition events, the artifact projection, and the ingest-time `jobs`
//! rows in ONE transaction, so a failed enqueue can never leave an artifact
//! ingested with a `ScanRequested` event but no `jobs` row (the dual-write
//! strand the method was added to close).
//!
//! Force-failure vector: an invalid `trigger_source` violates the
//! `jobs.trigger_source` CHECK (migration 009), so the in-tx scan insert
//! errors — the whole transition must then roll back.
//!
//! `DATABASE_URL`-gated; self-skips on hosts without a database (suite
//! convention). Uses `isolated_db_from` (a per-test throwaway database) for
//! isolation, so no `#[serial(hort_pg_db)]` key is required.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test ingest_enqueue_atomicity
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;

use chrono::Utc;
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
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");
    let repo_id = seed_repo(&pool).await;
    Some((pool, repo_id))
}

async fn lifecycle(pool: &PgPool) -> PgArtifactLifecycle {
    let event_store = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .expect("event store init"),
    );
    let artifact_repo = Arc::new(PgArtifactRepository::new(pool.clone()));
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
    // 32 hex chars padded to a valid 64-hex SHA-256 string.
    let sha = format!("{:0<64}", id.simple());
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
        upstream_published_at: None,
        uploaded_by: None,
        is_deleted: false,
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

async fn count(pool: &PgPool, sql: &str, id: Uuid) -> i64 {
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
