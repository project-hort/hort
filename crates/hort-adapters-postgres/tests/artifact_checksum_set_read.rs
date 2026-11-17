//! `PgArtifactRepository::find_live_rows_by_repo_and_checksums` —
//! the digest-set resolver behind the content-addressed curation
//! decisions.
//!
//! Four properties, each one a thing the curation resolver standing on
//! this read decides with:
//!
//! 1. **The whole equality range comes back.** Two live rows carrying
//!    one digest answer with two rows, not the `LIMIT 1` pick
//!    `find_by_repo_and_checksum` makes — a curation decision addressed
//!    by digest refuses to guess which row was reviewed, and it can only
//!    refuse if it is shown both.
//! 2. **Repository-scoped.** The index on `checksum_sha256` is not
//!    repository-scoped (`migrations/003_artifacts_cas.sql`), so the
//!    predicate is what keeps a decision inside the repository it was
//!    taken in.
//! 3. **Soft-deleted rows are excluded** (ADR 0030): a withdrawn row is
//!    not a row a curator can release or block.
//! 4. **The status travels with the row**, decoded through the one
//!    codec, so the resolver's verdict and the row are one observation.
//!
//! Gated on `DATABASE_URL`, like the rest of the suite; a missing
//! variable early-returns so the workspace `cargo test` stays green with
//! no database.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test artifact_checksum_set_read
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;

use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::artifact_repo::PgArtifactRepository;
use hort_adapters_postgres::event_store::PgEventStore;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::types::ContentHash;

async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

async fn repo_port(pool: &PgPool) -> PgArtifactRepository {
    let event_store = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .expect("PgEventStore::new"),
    );
    PgArtifactRepository::new(pool.clone(), event_store)
}

async fn seed_repository(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-digestset-{}", id.simple());
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $3,
               'oci'::repository_format,
               'hosted'::repository_type,
               'filesystem', $4,
               'local_only'::replication_priority
           )"#,
    )
    .bind(id)
    .bind(&key)
    .bind(&key)
    .bind(format!("/tmp/{key}"))
    .execute(pool)
    .await
    .expect("seed repository");
    id
}

/// Seed one `artifacts` row carrying `digest` at `path`, with
/// `quarantine_status` and an optional soft-delete stamp.
async fn seed_artifact(
    pool: &PgPool,
    repo: Uuid,
    digest: &str,
    path: &str,
    status: Option<&str>,
    deleted: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, path,
               size_bytes, checksum_sha256, content_type, storage_key,
               quarantine_status, deleted_at
           ) VALUES (
               $1, $2, 'digest-set-it', 'digest-set-it', $3,
               0, $4, 'application/octet-stream', $4,
               $5,
               CASE WHEN $6 THEN now() ELSE NULL END
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(path)
    .bind(digest)
    .bind(status)
    .bind(deleted)
    .execute(pool)
    .await
    .expect("seed artifact");
    id
}

fn hash(hex: &str) -> ContentHash {
    hex.parse().expect("64 lowercase hex characters")
}

const DIGEST_TWINS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DIGEST_SINGLE: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_ELSEWHERE: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const DIGEST_DELETED: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const DIGEST_ABSENT: &str = "5555555555555555555555555555555555555555555555555555555555555555";

/// The whole read, in one call: every live row of the equality range,
/// repository-scoped, soft-delete-excluded, each carrying its status.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_digest_set_read_answers_every_live_row_in_this_repository() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repository(&pool).await;
    let other_repo = seed_repository(&pool).await;

    // Identical bytes at two paths in one repository — the OCI case.
    let twin_one = seed_artifact(
        &pool,
        repo,
        DIGEST_TWINS,
        "blobs/twin-1",
        Some("quarantined"),
        false,
    )
    .await;
    let twin_two = seed_artifact(
        &pool,
        repo,
        DIGEST_TWINS,
        "blobs/twin-2",
        Some("released"),
        false,
    )
    .await;
    // One row, and a NULL status — the stored spelling of
    // `QuarantineStatus::None`.
    let single = seed_artifact(&pool, repo, DIGEST_SINGLE, "blobs/single", None, false).await;
    // The same digest in another repository, and a soft-deleted row in
    // this one: neither is this repository's live row.
    seed_artifact(
        &pool,
        other_repo,
        DIGEST_ELSEWHERE,
        "blobs/elsewhere",
        Some("quarantined"),
        false,
    )
    .await;
    seed_artifact(
        &pool,
        repo,
        DIGEST_DELETED,
        "blobs/deleted",
        Some("quarantined"),
        true,
    )
    .await;

    let port = repo_port(&pool).await;
    let rows = port
        .find_live_rows_by_repo_and_checksums(
            repo,
            &[
                hash(DIGEST_TWINS),
                hash(DIGEST_SINGLE),
                hash(DIGEST_ELSEWHERE),
                hash(DIGEST_DELETED),
                hash(DIGEST_ABSENT),
            ],
        )
        .await
        .expect("the digest-set read succeeds");

    let mut twins: Vec<Uuid> = rows
        .iter()
        .filter(|(h, _, _)| h.as_ref() == DIGEST_TWINS)
        .map(|(_, id, _)| *id)
        .collect();
    twins.sort_unstable();
    let mut expected = vec![twin_one, twin_two];
    expected.sort_unstable();
    assert_eq!(
        twins, expected,
        "both live rows carrying one digest come back — the read must not pick"
    );

    let statuses: Vec<QuarantineStatus> = rows
        .iter()
        .filter(|(h, _, _)| h.as_ref() == DIGEST_TWINS)
        .map(|(_, _, s)| *s)
        .collect();
    assert!(
        statuses.contains(&QuarantineStatus::Quarantined)
            && statuses.contains(&QuarantineStatus::Released),
        "each row carries its own status: {statuses:?}"
    );

    let single_rows: Vec<&(ContentHash, Uuid, QuarantineStatus)> = rows
        .iter()
        .filter(|(h, _, _)| h.as_ref() == DIGEST_SINGLE)
        .collect();
    assert_eq!(single_rows.len(), 1);
    assert_eq!(single_rows[0].1, single);
    assert_eq!(
        single_rows[0].2,
        QuarantineStatus::None,
        "a NULL status column decodes to `None` and nothing else"
    );

    for excluded in [DIGEST_ELSEWHERE, DIGEST_DELETED, DIGEST_ABSENT] {
        assert!(
            !rows.iter().any(|(h, _, _)| h.as_ref() == excluded),
            "{excluded} must not appear: another repository's row, a \
             soft-deleted row and an absent digest are all not this \
             repository's live rows"
        );
    }
    assert_eq!(rows.len(), 3, "exactly the three live matching rows");
}

/// An empty digest set answers with no rows and issues no statement —
/// the one question with only one possible answer.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_empty_digest_set_answers_without_a_round_trip() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repository(&pool).await;
    seed_artifact(
        &pool,
        repo,
        DIGEST_SINGLE,
        "blobs/single",
        Some("quarantined"),
        false,
    )
    .await;

    let port = repo_port(&pool).await;
    let rows = port
        .find_live_rows_by_repo_and_checksums(repo, &[])
        .await
        .expect("an empty set is not an error");
    assert!(rows.is_empty());
}

/// The plural read and the `LIMIT 1` singular read answer the same
/// question differently, and that difference is why both exist: the
/// singular one picks a row where the plural one hands back every
/// candidate. Pinned so a future "simplification" that routes the
/// curation resolver through the singular read fails here.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_singular_read_picks_where_the_plural_read_enumerates() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repository(&pool).await;
    seed_artifact(
        &pool,
        repo,
        DIGEST_TWINS,
        "blobs/twin-1",
        Some("quarantined"),
        false,
    )
    .await;
    seed_artifact(
        &pool,
        repo,
        DIGEST_TWINS,
        "blobs/twin-2",
        Some("quarantined"),
        false,
    )
    .await;

    let port = repo_port(&pool).await;
    let picked = port
        .find_by_repo_and_checksum(repo, &hash(DIGEST_TWINS))
        .await
        .expect("the singular read succeeds");
    assert!(
        picked.is_some(),
        "the singular read answers with one arbitrary row"
    );
    let enumerated = port
        .find_live_rows_by_repo_and_checksums(repo, &[hash(DIGEST_TWINS)])
        .await
        .expect("the plural read succeeds");
    assert_eq!(
        enumerated.len(),
        2,
        "the plural read enumerates, which is what lets its caller refuse"
    );
}

/// A status the column's CHECK still admits but the codec cannot
/// classify fails the read instead of answering with a state.
///
/// Migration `003`'s CHECK accepts three spellings no code writes any
/// more (`unscanned`, `clean`, `flagged`), so the row is schema-legal
/// and only the codec stands between it and a serving decision. This
/// read decides a curator release, and the permissive
/// `QuarantineStatus::None` is both the value a substituted decode
/// lands on and the state the bulk waive's own guard would read as
/// "nothing to release" — so a discarded decode error here would not
/// degrade the resolution, it would invert it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_unclassifiable_status_fails_the_read_rather_than_answering() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repository(&pool).await;
    let id = seed_artifact(
        &pool,
        repo,
        DIGEST_SINGLE,
        "blobs/legacy",
        Some("unscanned"),
        false,
    )
    .await;

    let port = repo_port(&pool).await;
    let err = port
        .find_live_rows_by_repo_and_checksums(repo, &[hash(DIGEST_SINGLE)])
        .await
        .expect_err("an unclassifiable status must not resolve to a state");
    let message = err.to_string();
    assert!(
        message.contains("unclassifiable quarantine_status"),
        "the refusal must say what it could not read: {message}"
    );
    assert!(
        message.contains("find_live_rows_by_repo_and_checksums")
            && message.contains(&id.to_string()),
        "the refusal must name the read and the row, so the bad row is findable: {message}"
    );
}
