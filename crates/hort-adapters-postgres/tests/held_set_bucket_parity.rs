//! **Bucket-rule parity: the Rust predicate and the SQL agree, over the
//! same kind sets.**
//!
//! The held-set overview splits each repository's held set into the
//! parent-gated blob constituents and the artifacts held in their own
//! right, because the operator action differs (ADR 0039 — a blob cannot
//! carry its own attestation, so a constituent is waiting on its
//! *parent manifest's* signature and can never acquire one of its own).
//!
//! The rule has exactly one definition in Rust,
//! [`is_parent_gated_blob_constituent_kinds`], and the aggregate does
//! **not** re-implement it: the two kind lists reach the query as
//! `text[]` parameters and the SQL forms only the boolean
//!
//! ```text
//! bool_or(kind = ANY($blob)) AND bool_and(kind = ANY($blob) OR kind = ANY($self))
//! ```
//!
//! That shape is a transcription, and a transcription is exactly the
//! thing that drifts silently. **This test is what fails if either side
//! is edited alone**: for every reference shape in [`shapes`] it seeds a
//! held artifact carrying those `content_references` kinds, asks the
//! adapter which bucket the row landed in, asks the Rust predicate the
//! same question over the same kinds, and requires the two answers to be
//! the same answer.
//!
//! The shapes are not a sample of plausible inputs — they are the rule's
//! own case analysis:
//!
//! - the empty set (the Rust predicate's empty-iterator case, and the
//!   SQL's all-`NULL` `LEFT JOIN` row);
//! - a self-referential edge alone (every artifact's own ingest writes
//!   one, so this is the false positive the kind filter exists to
//!   prevent);
//! - each blob kind alone, and both together;
//! - a blob kind beside a self-referential one (the common real shape);
//! - each disqualifying kind — `oci_index_member` (a child *manifest*,
//!   which can be signed in its own right) and `oci_subject` (an
//!   attestation points at this artifact) — alone and beside a blob
//!   edge, because the "every row" clause is what the `bool_and` leg
//!   stands for;
//! - an unknown/future kind, alone and beside a blob edge: the
//!   allowlist is closed, so an unfamiliar edge disqualifies the
//!   bucket on both paths rather than being ignored by one of them.
//!
//! The kind lists themselves are never typed here: the test asserts
//! `PARENT_GATE_BLOB_KINDS` and `SELF_REFERENTIAL_KINDS` are what it
//! thinks they are, and otherwise reads them, so adding a kind to either
//! list changes what this test drives rather than leaving it behind.
//!
//! ```bash
//! DATABASE_URL=postgres://… \
//!   cargo test -p hort-adapters-postgres --test held_set_bucket_parity
//! ```

#![allow(clippy::expect_used)]

use std::env;

use chrono::{Duration, Utc};
use serde_json::json;
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::held_set_reader::PgHeldSetReader;
use hort_app::use_cases::referenced_descendant::{
    is_parent_gated_blob_constituent_kinds, PARENT_GATE_BLOB_KINDS, SELF_REFERENTIAL_KINDS,
};
use hort_domain::ports::held_set_reader::{
    ConstituentKindSets, HeldBucket, HeldCandidateQuery, HeldSetReader,
};

/// A disqualifying tree edge whose target is a child **manifest**.
const INDEX_MEMBER: &str = "oci_index_member";
/// A disqualifying tree edge: an attestation points at this artifact.
const SUBJECT: &str = "oci_subject";
/// A kind neither list knows. The allowlist is closed, so this
/// disqualifies the bucket — on both paths or the parity is broken.
const UNKNOWN: &str = "some_future_edge_kind";

/// `(label, reference kinds)` — the rule's case analysis. See the module
/// docs for why each shape is here.
///
/// Spelled as a function rather than a `const` so the blob and
/// self-referential kinds are *read* from their one definition instead
/// of re-typed.
fn shapes() -> Vec<(&'static str, Vec<&'static str>)> {
    let blob_a = PARENT_GATE_BLOB_KINDS[0];
    let blob_b = PARENT_GATE_BLOB_KINDS[1];
    let own_a = SELF_REFERENTIAL_KINDS[0];
    let own_b = SELF_REFERENTIAL_KINDS[1];
    vec![
        ("no references at all", vec![]),
        ("its own primary-content edge alone", vec![own_a]),
        ("its own metadata-blob edge alone", vec![own_b]),
        ("both of its own edges", vec![own_a, own_b]),
        ("one blob edge", vec![blob_a]),
        ("the other blob edge", vec![blob_b]),
        ("both blob edges", vec![blob_a, blob_b]),
        ("a blob edge beside its own", vec![blob_a, own_a]),
        (
            "both blob edges beside both of its own",
            vec![blob_a, blob_b, own_a, own_b],
        ),
        ("a child-manifest edge alone", vec![INDEX_MEMBER]),
        (
            "a child-manifest edge beside a blob edge",
            vec![blob_a, INDEX_MEMBER],
        ),
        ("an attestation subject edge alone", vec![SUBJECT]),
        (
            "an attestation subject edge beside a blob edge",
            vec![blob_a, SUBJECT],
        ),
        ("an unknown edge alone", vec![UNKNOWN]),
        ("an unknown edge beside a blob edge", vec![blob_a, UNKNOWN]),
        (
            "every disqualifying edge at once",
            vec![blob_a, own_a, INDEX_MEMBER, SUBJECT, UNKNOWN],
        ),
    ]
}

/// Guard against the shape table quietly becoming a different table:
/// the kind lists are read, not typed, so this is the one place their
/// contents are asserted.
#[test]
fn the_shapes_are_built_from_the_one_rust_definition() {
    assert_eq!(
        PARENT_GATE_BLOB_KINDS.to_vec(),
        vec!["oci_config", "oci_layer"],
        "the blob-kind list changed — re-read the shapes before trusting them"
    );
    assert_eq!(
        SELF_REFERENTIAL_KINDS.to_vec(),
        vec!["primary_content", "metadata_blob"],
        "the self-referential list changed — re-read the shapes"
    );
    // Both buckets must actually be exercised, or "the two paths agree"
    // could be satisfied by a table that only ever asks one question.
    let constituents = shapes()
        .iter()
        .filter(|(_, kinds)| is_parent_gated_blob_constituent_kinds(kinds.iter().copied()))
        .count();
    assert!(
        constituents > 0 && constituents < shapes().len(),
        "the shape table must contain both constituents and non-constituents; \
         {constituents} of {} are constituents",
        shapes().len()
    );
}

/// The parity itself.
///
/// One repository, one `Required` policy with an already-elapsed window,
/// one held artifact per shape. The adapter's aggregate and page are
/// both read, so neither statement can be the one that drifted.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_sql_bucket_and_the_rust_predicate_agree_on_every_shape() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    let repo = seed_repo(&pool).await;
    seed_required_policy(&pool, repo).await;

    // Seed one held artifact per shape, each with its own content hash
    // so its reference set is its own.
    let mut seeded: Vec<(&'static str, Uuid, bool)> = Vec::new();
    for (index, (label, kinds)) in shapes().into_iter().enumerate() {
        let hash = content_hash(index);
        let artifact = seed_held_artifact(&pool, repo, &format!("shape-{index}"), &hash).await;
        for kind in &kinds {
            seed_reference(&pool, repo, artifact, &hash, kind).await;
        }
        // The Rust side, over exactly the kinds that were seeded.
        let expected = is_parent_gated_blob_constituent_kinds(kinds.iter().copied());
        seeded.push((label, artifact, expected));
    }

    let reader = PgHeldSetReader::new(pool.clone());
    let kinds = ConstituentKindSets {
        blob_kinds: &PARENT_GATE_BLOB_KINDS,
        self_referential_kinds: &SELF_REFERENTIAL_KINDS,
    };

    // The SQL side, read off the drill-down: which bucket did each row
    // actually land in?
    let mut sql_bucket: Vec<(Uuid, HeldBucket)> = Vec::new();
    for bucket in HeldBucket::all() {
        let rows = reader
            .list_candidates(HeldCandidateQuery {
                now: Utc::now(),
                kinds,
                bucket,
                repository_id: Some(repo),
                after: None,
                limit: 500,
            })
            .await
            .expect("held-set page");
        for row in rows {
            assert_eq!(
                row.bucket, bucket,
                "the page projected a row into a bucket it was not asked for"
            );
            sql_bucket.push((row.artifact_id, bucket));
        }
    }

    assert_eq!(
        sql_bucket.len(),
        seeded.len(),
        "every seeded artifact must appear in exactly one bucket; \
         seeded {} and the two pages returned {}",
        seeded.len(),
        sql_bucket.len()
    );

    for (label, artifact, expected) in &seeded {
        let observed = sql_bucket
            .iter()
            .find(|(id, _)| id == artifact)
            .map(|(_, bucket)| *bucket)
            .unwrap_or_else(|| panic!("{label}: the artifact reached neither bucket"));
        assert_eq!(
            observed,
            HeldBucket::from_is_constituent(*expected),
            "{label}: the SQL bucketed this row as {observed} while \
             `is_parent_gated_blob_constituent_kinds` says \
             is_constituent={expected}. The two sides of the bucket rule \
             have drifted — the kind lists are parameters and the SQL must \
             form only the boolean"
        );
    }

    // The aggregate counts the same split. Reading both statements is
    // what keeps "the SQL agrees" from meaning "one of the two
    // statements agrees".
    let buckets = reader
        .aggregate_candidates(Utc::now(), kinds)
        .await
        .expect("held-set aggregate");
    for bucket in HeldBucket::all() {
        let expected = seeded
            .iter()
            .filter(|(_, _, is_constituent)| {
                HeldBucket::from_is_constituent(*is_constituent) == bucket
            })
            .count() as u64;
        let counted = buckets
            .iter()
            .filter(|b| b.repository_id == repo && b.bucket == bucket)
            .map(|b| b.artifact_count)
            .sum::<u64>();
        assert_eq!(
            counted, expected,
            "the aggregate counts {counted} artifacts in the {bucket} bucket \
             where the Rust predicate puts {expected}"
        );
    }
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/// Per-test isolated database. `None` only when `DATABASE_URL` is unset.
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

/// A distinct 64-hex hash per shape.
fn content_hash(index: usize) -> String {
    format!("{:064x}", 0x5eed_0000_u64 + index as u64)
}

async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("bucket-parity-{}", id.simple());
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend,
               storage_path, replication_priority
           ) VALUES (
               $1, $2, $2, 'oci'::repository_format,
               'hosted'::repository_type, 'filesystem', $3,
               'local_only'::replication_priority
           )"#,
    )
    .bind(id)
    .bind(&key)
    .bind(format!("/tmp/{key}"))
    .execute(pool)
    .await
    .expect("seed repository");
    id
}

/// A repo-scoped `provenance_mode = required` policy with a 60 s
/// quarantine duration, so an artifact whose window opened an hour ago
/// is past its deadline and therefore in the category.
async fn seed_required_policy(pool: &PgPool, repo: Uuid) {
    sqlx::query(
        r#"INSERT INTO public.policy_projections (
               policy_id, name, scope, severity_threshold,
               rescan_interval_hours, quarantine_duration_secs,
               require_approval, provenance_mode, archived, stream_version
           ) VALUES ($1, $2, $3, 'high', 24, 60, false, 'required', false, 1)"#,
    )
    .bind(Uuid::new_v4())
    .bind(format!("bucket-parity-policy-{}", Uuid::new_v4().simple()))
    .bind(json!({ "Repository": repo }))
    .execute(pool)
    .await
    .expect("seed policy");
}

async fn seed_held_artifact(pool: &PgPool, repo: Uuid, name: &str, hash: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key,
               quarantine_status, created_at, updated_at,
               quarantine_window_start
           ) VALUES (
               $1, $2, $3, $3, NULL, $4,
               10, $5, 'application/octet-stream', $5,
               'quarantined', now(), now(), $6
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(name)
    .bind(format!("{name}/blobs/{}", id.simple()))
    .bind(hash)
    .bind(Utc::now() - Duration::seconds(3600))
    .execute(pool)
    .await
    .expect("seed artifact");
    id
}

/// One inbound `content_references` edge naming this artifact's content
/// as its target — the same `(repository_id, target_content_hash)`
/// scoping `ContentReferenceIndex::find_by_target` reads through.
///
/// The `source_artifact_id` is the artifact itself for every kind, which
/// is what makes the primary key `(repository_id, source_artifact_id,
/// kind)` admit one row per kind per shape. The predicate reads only
/// `kind`, so the source identity is irrelevant to what is under test.
async fn seed_reference(pool: &PgPool, repo: Uuid, artifact: Uuid, hash: &str, kind: &str) {
    sqlx::query(
        r#"INSERT INTO public.content_references
               (source_artifact_id, target_content_hash, kind, repository_id)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(artifact)
    .bind(hash)
    .bind(kind)
    .bind(repo)
    .execute(pool)
    .await
    .expect("seed content reference");
}
