//! Content-reference edge atomicity integration tests.
//!
//! `PgArtifactLifecycle::commit_transition_with_enqueues` must commit the
//! transition events, the artifact projection and the artifact's
//! `content_references` edges in ONE transaction. The hazard a failed edge
//! leaves behind is not a lagging projection: the storage GC deletes a CAS
//! blob exactly when no `content_references` row targets its hash, so an
//! artifact committed without its `primary_content` edge counts **zero**
//! against its own content, and because CAS deduplicates, a released sibling
//! carrying the same bytes drives the count to zero and authorises the
//! delete. A missing edge brings collection forward and leaves a live,
//! servable artifact pointing at bytes that are gone.
//!
//! Force-failure vector: an edge whose `repository_id` names no repository
//! violates `content_references_repository_id_fkey`, so the in-tx upsert
//! errors — the whole transition must then roll back. The artifact's own
//! `repository_id` stays valid, so nothing but the edge is wrong.
//!
//! What these tests prove is the **rollback**, not the end state. That the
//! artifact and the edge are both present after a successful commit was true
//! before the edges moved into the transaction too, whenever nothing went
//! wrong; the load-bearing assertion is that a failed edge leaves **neither**
//! the artifact row **nor** the event stream behind.
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
//!   cargo test -p hort-adapters-postgres --test content_reference_edge_atomicity
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
use hort_domain::events::{system_actor, ArtifactIngested, DomainEvent, IngestSource, StreamId};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::content_reference_index::ContentReference;
use hort_domain::ports::event_store::{AppendEvents, EventToAppend, ExpectedVersion};
use hort_domain::types::ContentHash;

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
    let key = format!("it-edgeatomic-{}", id.simple());
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
    // unique per artifact.
    let sha = id.simple().to_string().repeat(2);
    Artifact {
        id,
        repository_id: repo_id,
        name: "edge-atomic".into(),
        name_as_published: "edge-atomic".into(),
        version: Some("1.0.0".into()),
        path: format!("simple/edge-atomic/{}.tar.gz", id.simple()),
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
        events: vec![EventToAppend {
            event_id: Uuid::new_v4(),
            event: DomainEvent::ArtifactIngested(ArtifactIngested {
                artifact_id: a.id,
                repository_id: a.repository_id,
                name: a.name.clone(),
                version: a.version.clone(),
                sha256: a.sha256_checksum.clone(),
                size_bytes: a.size_bytes,
                source: IngestSource::Direct,
                metadata: serde_json::Value::Null,
                metadata_blob: None,
                upstream_published_at: None,
            }),
        }],
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: system_actor(),
    }
}

/// An ingest edge: `source` claims `target` under `kind`, in `repo`.
fn edge(repo: Uuid, source: Uuid, target: &ContentHash, kind: &str) -> ContentReference {
    ContentReference {
        source_artifact_id: source,
        target_content_hash: target.clone(),
        kind: kind.to_string(),
        metadata: serde_json::Value::Object(serde_json::Map::new()),
        repository_id: repo,
        recorded_at: Utc::now(),
    }
}

/// A second, distinct, valid content hash — the CAS-resident metadata blob
/// an ingest's `metadata_blob` edge targets.
fn other_hash() -> ContentHash {
    Uuid::new_v4()
        .simple()
        .to_string()
        .repeat(2)
        .parse()
        .expect("valid sha256")
}

async fn count(pool: &PgPool, sql: &'static str, id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>(sql)
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count query")
}

/// Events on the artifact's own stream, by stream id rather than by
/// artifact id: the proof has to be that no event *record* survives, and
/// `events` is keyed by `stream_id`.
async fn stream_event_count(pool: &PgPool, artifact_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM public.events WHERE stream_id = $1")
        .bind(StreamId::artifact(artifact_id).to_string())
        .fetch_one(pool)
        .await
        .expect("event count query")
}

/// **The acceptance.** A failed edge insert leaves neither the artifact row
/// nor a single event on its stream. Not "the edge is missing" — the whole
/// transition is gone, so there is no committed artifact for the storage GC
/// to out-live.
#[tokio::test]
#[serial(hort_pg_db)]
async fn edge_failure_rolls_back_the_artifact_and_its_events() {
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
            &[],
            // The artifact's repository is real; the EDGE names one that is
            // not, so `content_references_repository_id_fkey` fires on the
            // in-tx upsert and nothing else in the transaction is at fault.
            &[edge(
                Uuid::new_v4(),
                a.id,
                &a.sha256_checksum,
                "primary_content",
            )],
        )
        .await;

    assert!(
        result.is_err(),
        "a failed edge must fail the commit, not be dropped — a committed \
         artifact with no row claiming its bytes is collectable by the GC"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.artifacts WHERE id = $1",
            a.id
        )
        .await,
        0,
        "the artifact save must roll back with the failed edge",
    );
    assert_eq!(
        stream_event_count(&pool, a.id).await,
        0,
        "no event may survive the rolled-back transition — the event stream \
         is the rebuild authority, and an `ArtifactIngested` left here would \
         re-materialise the artifact the rollback was supposed to erase",
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.content_references WHERE source_artifact_id = $1",
            a.id
        )
        .await,
        0,
        "and no edge either",
    );
}

/// The same rollback when the artifact's FIRST edge is valid and a LATER one
/// is not. The transaction has already written a `content_references` row by
/// then, so this is the case where a per-edge commit would have left the
/// partial set — the one an all-or-nothing claim actually has to cover.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_later_edge_failure_rolls_back_the_earlier_edge_too() {
    let Some((pool, repo_id)) = maybe_setup().await else {
        return;
    };
    let lc = lifecycle(&pool).await;
    let a = artifact(repo_id);
    let blob = other_hash();

    let result = lc
        .commit_transition_with_enqueues(
            &a,
            ingest_events(&a),
            None,
            &[],
            &[
                edge(repo_id, a.id, &a.sha256_checksum, "primary_content"),
                edge(Uuid::new_v4(), a.id, &blob, "metadata_blob"),
            ],
        )
        .await;

    assert!(
        result.is_err(),
        "the invalid second edge must fail the commit"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.content_references WHERE source_artifact_id = $1",
            a.id
        )
        .await,
        0,
        "the valid first edge must roll back with the failed second one",
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.artifacts WHERE id = $1",
            a.id
        )
        .await,
        0,
        "and the artifact with both",
    );
    assert_eq!(stream_event_count(&pool, a.id).await, 0, "and the events");
}

/// Happy path, kept as the counter-assertion: without it the rollback tests
/// above would pass just as well against a method that never writes an edge
/// at all.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_valid_commit_lands_the_artifact_and_every_edge() {
    let Some((pool, repo_id)) = maybe_setup().await else {
        return;
    };
    let lc = lifecycle(&pool).await;
    let a = artifact(repo_id);
    let blob = other_hash();

    lc.commit_transition_with_enqueues(
        &a,
        ingest_events(&a),
        None,
        &[],
        &[
            edge(repo_id, a.id, &a.sha256_checksum, "primary_content"),
            edge(repo_id, a.id, &blob, "metadata_blob"),
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
    let kinds: Vec<(String, String)> = sqlx::query_as(
        "SELECT kind, target_content_hash FROM public.content_references \
         WHERE source_artifact_id = $1 ORDER BY kind",
    )
    .bind(a.id)
    .fetch_all(&pool)
    .await
    .expect("edge query");
    assert_eq!(
        kinds,
        vec![
            ("metadata_blob".to_string(), blob.as_ref().to_owned()),
            (
                "primary_content".to_string(),
                a.sha256_checksum.as_ref().to_owned()
            ),
        ],
        "both edges land, each targeting its own hash",
    );
    // Counter-assertion for `stream_event_count`: the rollback tests read
    // zero through that helper, and a mis-spelled `stream_id` would read
    // zero here too. It must see the event this commit actually appended.
    assert_eq!(
        stream_event_count(&pool, a.id).await,
        1,
        "the committed `ArtifactIngested` is visible to the same query the \
         rollback assertions use",
    );
}

/// Re-committing the same transition's edges is an upsert, not a duplicate
/// -key failure. Load-bearing for the adapter's own contention retry: an
/// abort reported *after* a row landed re-runs the whole transaction, and a
/// re-run that tripped the primary key would turn a transient abort into a
/// failed ingest.
#[tokio::test]
#[serial(hort_pg_db)]
async fn re_committing_an_edge_upserts_rather_than_conflicting() {
    let Some((pool, repo_id)) = maybe_setup().await else {
        return;
    };
    let lc = lifecycle(&pool).await;
    let a = artifact(repo_id);
    let edges = [edge(repo_id, a.id, &a.sha256_checksum, "primary_content")];

    lc.commit_transition_with_enqueues(&a, ingest_events(&a), None, &[], &edges)
        .await
        .expect("the first commit must succeed");

    // A second transition on the same artifact, carrying the same edge. The
    // stream is at position 0 now, so the append expects that rather than
    // `NoStream`.
    let mut second = ingest_events(&a);
    second.expected_version = ExpectedVersion::Exact(0);
    lc.commit_transition_with_enqueues(&a, second, None, &[], &edges)
        .await
        .expect("re-presenting the same edge must upsert, not conflict");

    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.content_references WHERE source_artifact_id = $1",
            a.id
        )
        .await,
        1,
        "one row per (repo, source, target, kind) — the second write refreshed it",
    );
}

/// The rollback holds for an edge onto **foreign** bytes — the shape every
/// OCI tree edge has (`oci_subject` onto a subject image, `oci_index_member`
/// onto a child manifest, `oci_config` / `oci_layer` onto a blob).
///
/// Worth its own case because the recovery story is different, not because
/// the transaction is. A missing `primary_content` edge is drift the
/// refcount-reconcile sweep converges, since `artifacts.checksum_sha256`
/// records what that edge should have said. Nothing records what a manifest
/// references, so a tree edge that never landed is unrecoverable from the
/// relational store: the sweep mints none, and the only repair is re-reading
/// manifest bodies out of CAS. The target is also somebody else's content, so
/// the artifact that loses its claim is not the one that would notice.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_foreign_target_edge_failure_rolls_back_the_whole_transition() {
    let Some((pool, repo_id)) = maybe_setup().await else {
        return;
    };
    let lc = lifecycle(&pool).await;
    let a = artifact(repo_id);
    // The referrer's own content, then a claim on another artifact's bytes.
    let subject = other_hash();

    let result = lc
        .commit_transition_with_enqueues(
            &a,
            ingest_events(&a),
            None,
            &[],
            &[
                edge(repo_id, a.id, &a.sha256_checksum, "primary_content"),
                edge(Uuid::new_v4(), a.id, &subject, "oci_subject"),
            ],
        )
        .await;

    assert!(
        result.is_err(),
        "a failed claim on foreign bytes must fail the commit"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.content_references WHERE source_artifact_id = $1",
            a.id
        )
        .await,
        0,
        "no edge survives — including the referrer's own, written first",
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.artifacts WHERE id = $1",
            a.id
        )
        .await,
        0,
        "and no referrer is left live over a subject that lost its claim",
    );
    assert_eq!(stream_event_count(&pool, a.id).await, 0, "and no events");
}

/// One transition carrying the SAME `(target, kind)` twice is an upsert, not
/// a duplicate-key failure.
///
/// This shape is reachable only now that a caller's claims ride the
/// transition: an OCI image manifest may legally list the same layer digest
/// more than once (identical empty layers are routine), and an index may name
/// a child twice, so the claim set handed over is not deduplicated. Before,
/// each edge was its own transaction and the second simply upserted the
/// first. `upsert_edges_in_tx` issues one statement per edge for exactly this
/// reason — a single multi-row `INSERT … ON CONFLICT DO UPDATE` cannot touch
/// the same row twice and would turn a legal manifest into a failed push.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_repeated_edge_within_one_set_upserts_rather_than_conflicting() {
    let Some((pool, repo_id)) = maybe_setup().await else {
        return;
    };
    let lc = lifecycle(&pool).await;
    let a = artifact(repo_id);
    let layer = other_hash();

    lc.commit_transition_with_enqueues(
        &a,
        ingest_events(&a),
        None,
        &[],
        &[
            edge(repo_id, a.id, &a.sha256_checksum, "primary_content"),
            edge(repo_id, a.id, &layer, "oci_layer"),
            edge(repo_id, a.id, &layer, "oci_layer"),
        ],
    )
    .await
    .expect("a duplicated claim within one set must upsert, not conflict");

    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM public.content_references WHERE source_artifact_id = $1",
            a.id
        )
        .await,
        2,
        "the duplicate collapses onto one row; the distinct kinds stay two",
    );
}
