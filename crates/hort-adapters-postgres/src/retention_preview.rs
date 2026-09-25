//! PostgreSQL implementation of retention preview's read-only purge
//! simulation.
//!
//! The query constructs the exact target set purge would remove for the
//! supplied artifact set, then excludes every target that still has a
//! source edge outside that set. The fallback for a source with no projected
//! edges mirrors `PgPurgeGcPort::purge_artifact_refs`: primary content plus a
//! non-empty metadata blob. No row is locked, deleted, or inserted.

use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::retention_preview::{RetentionContentSimulation, RetentionPreview};
use hort_domain::types::ContentHash;

use crate::{map_sqlx_error, BoxFuture};

/// Read-only Postgres simulator for retention preview accounting.
pub struct PgRetentionPreview {
    pool: PgPool,
}

impl PgRetentionPreview {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl RetentionPreview for PgRetentionPreview {
    fn reclaimable_content<'a>(
        &'a self,
        artifact_ids: &'a [Uuid],
        max_artifacts: usize,
        max_targets: u32,
    ) -> BoxFuture<'a, DomainResult<RetentionContentSimulation>> {
        Box::pin(async move {
            if artifact_ids.len() > max_artifacts {
                return Ok(RetentionContentSimulation::Omitted);
            }
            if artifact_ids.is_empty() {
                return Ok(RetentionContentSimulation::Exact(Vec::new()));
            }

            let result_limit = i64::from(max_targets) + 1;
            let rows = sqlx::query(
                r#"
                WITH candidate_ids AS (
                    SELECT unnest($1::uuid[]) AS artifact_id
                ),
                projected_sources AS (
                    SELECT DISTINCT cr.source_artifact_id
                      FROM content_references cr
                      JOIN candidate_ids c
                        ON c.artifact_id = cr.source_artifact_id
                ),
                removed_targets AS (
                    SELECT cr.target_content_hash
                      FROM content_references cr
                      JOIN candidate_ids c
                        ON c.artifact_id = cr.source_artifact_id
                    UNION
                    SELECT a.checksum_sha256
                      FROM artifacts a
                      JOIN candidate_ids c ON c.artifact_id = a.id
                 LEFT JOIN projected_sources ps ON ps.source_artifact_id = a.id
                     WHERE ps.source_artifact_id IS NULL
                    UNION
                    SELECT am.metadata_blob
                      FROM artifact_metadata am
                      JOIN candidate_ids c ON c.artifact_id = am.artifact_id
                 LEFT JOIN projected_sources ps ON ps.source_artifact_id = am.artifact_id
                     WHERE ps.source_artifact_id IS NULL
                       AND am.metadata_blob IS NOT NULL
                       AND btrim(am.metadata_blob) <> ''
                )
                SELECT DISTINCT rt.target_content_hash
                  FROM removed_targets rt
                 WHERE NOT EXISTS (
                       SELECT 1
                         FROM content_references survivor
                        WHERE survivor.target_content_hash = rt.target_content_hash
                          AND NOT (survivor.source_artifact_id = ANY($1::uuid[]))
                 )
                 ORDER BY rt.target_content_hash
                 LIMIT $2
                "#,
            )
            .bind(artifact_ids)
            .bind(result_limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "retention_preview", "reclaimable_content"))?;

            if rows.len() > max_targets as usize {
                return Ok(RetentionContentSimulation::Omitted);
            }

            let mut hashes = Vec::with_capacity(rows.len());
            for row in rows {
                let raw: String = row.try_get("target_content_hash").map_err(|e| {
                    DomainError::Invariant(format!(
                        "retention_preview target_content_hash decode: {e}"
                    ))
                })?;
                hashes.push(raw.trim().parse::<ContentHash>().map_err(|e| {
                    DomainError::Invariant(format!(
                        "retention_preview corrupt target_content_hash {raw:?}: {e}"
                    ))
                })?);
            }
            Ok(RetentionContentSimulation::Exact(hashes))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use serial_test::serial;
    use std::sync::Arc;

    use hort_app::event_store_publisher::EventStorePublisher;
    use hort_app::use_cases::retention_use_case::{RetentionCandidate, RetentionUseCase};
    use hort_domain::events::{
        system_actor, ArtifactIngested, DomainEvent, IngestSource, StreamId,
    };
    use hort_domain::ports::event_store::{
        AppendEvents, EventStore, EventToAppend, ExpectedVersion, ReadFrom,
    };
    use hort_domain::ports::retention_candidate_reader::RetentionCandidateReader;
    use hort_domain::retention::{
        PolicyPredicate, RetentionEvaluationMode, RetentionPolicy, RetentionPolicyEvent,
        RetentionScope,
    };

    use crate::event_store::PgEventStore;
    use crate::retention_candidate_reader::PgRetentionCandidateReader;
    use crate::retention_scan_reader::PgRetentionScanReader;

    const SHARED_PRIMARY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SURVIVING_METADATA: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const SURVIVING_CHILD: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";
    const EXCLUSIVE_CHILD: &str =
        "4444444444444444444444444444444444444444444444444444444444444444";

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;
        Some(pool)
    }

    async fn seed_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("retention-preview-{}", id.simple());
        sqlx::query(
            r#"INSERT INTO repositories (
                   id, key, name, format, repo_type, storage_backend, storage_path,
                   replication_priority
               ) VALUES (
                   $1, $2, $2, 'generic', 'hosted', 'filesystem', $3, 'local_only'
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

    async fn seed_artifact(pool: &PgPool, repository_id: Uuid, hash: &str, label: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   quarantine_status
               ) VALUES (
                   $1, $2, $3, $3, '1.0.0', $4,
                   1, $5, 'application/octet-stream', $4, 'released'
               )"#,
        )
        .bind(id)
        .bind(repository_id)
        .bind(label)
        .bind(format!("{label}/{}", id.simple()))
        .bind(hash)
        .execute(pool)
        .await
        .expect("seed artifact");
        id
    }

    async fn seed_edge(
        pool: &PgPool,
        repository_id: Uuid,
        source_artifact_id: Uuid,
        kind: &str,
        target: &str,
    ) {
        sqlx::query(
            r#"INSERT INTO content_references (
                   repository_id, source_artifact_id, kind, target_content_hash
               ) VALUES ($1, $2, $3, $4)"#,
        )
        .bind(repository_id)
        .bind(source_artifact_id)
        .bind(kind)
        .bind(target)
        .execute(pool)
        .await
        .expect("seed content edge");
    }

    #[test]
    fn adapter_implements_port() {
        fn assert_port<T: RetentionPreview>() {}
        assert_port::<PgRetentionPreview>();
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn shared_targets_are_excluded_from_literal_freed_byte_total() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repository_id = seed_repo(&pool).await;
        let first = seed_artifact(&pool, repository_id, SHARED_PRIMARY, "first").await;
        let second = seed_artifact(&pool, repository_id, SHARED_PRIMARY, "second").await;
        let metadata_survivor = seed_artifact(
            &pool,
            repository_id,
            SURVIVING_METADATA,
            "metadata-survivor",
        )
        .await;
        let manifest_survivor =
            seed_artifact(&pool, repository_id, SURVIVING_CHILD, "manifest-survivor").await;

        seed_edge(
            &pool,
            repository_id,
            first,
            "primary_content",
            SHARED_PRIMARY,
        )
        .await;
        seed_edge(
            &pool,
            repository_id,
            first,
            "metadata_blob",
            SURVIVING_METADATA,
        )
        .await;
        seed_edge(
            &pool,
            repository_id,
            second,
            "primary_content",
            SHARED_PRIMARY,
        )
        .await;
        seed_edge(&pool, repository_id, second, "oci_config", SURVIVING_CHILD).await;
        seed_edge(&pool, repository_id, second, "oci_layer:0", EXCLUSIVE_CHILD).await;
        seed_edge(
            &pool,
            repository_id,
            metadata_survivor,
            "primary_content",
            SURVIVING_METADATA,
        )
        .await;
        seed_edge(
            &pool,
            repository_id,
            manifest_survivor,
            "oci_layer:0",
            SURVIVING_CHILD,
        )
        .await;

        let simulator = PgRetentionPreview::new(pool.clone());
        let RetentionContentSimulation::Exact(hashes) = simulator
            .reclaimable_content(&[first, second], 10, 10)
            .await
            .expect("simulate")
        else {
            panic!("small fixture must be exact");
        };
        let actual: Vec<&str> = hashes.iter().map(AsRef::as_ref).collect();
        assert_eq!(actual, vec![SHARED_PRIMARY, EXCLUSIVE_CHILD]);

        let freed_bytes: u64 = hashes
            .iter()
            .map(|hash| match hash.as_ref() {
                SHARED_PRIMARY => 11,
                EXCLUSIVE_CHILD => 29,
                SURVIVING_METADATA => 101,
                SURVIVING_CHILD => 103,
                other => panic!("unexpected target {other}"),
            })
            .sum();
        assert_eq!(freed_bytes, 40);

        let remaining_edges: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM content_references WHERE source_artifact_id = ANY($1)",
        )
        .bind([first, second])
        .fetch_one(&pool)
        .await
        .expect("count edges");
        assert_eq!(remaining_edges, 5, "simulation must not mutate edges");
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn bounds_omit_instead_of_returning_partial_targets() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repository_id = seed_repo(&pool).await;
        let source = seed_artifact(&pool, repository_id, SHARED_PRIMARY, "bounded").await;
        seed_edge(
            &pool,
            repository_id,
            source,
            "primary_content",
            SHARED_PRIMARY,
        )
        .await;
        seed_edge(
            &pool,
            repository_id,
            source,
            "metadata_blob",
            EXCLUSIVE_CHILD,
        )
        .await;
        let simulator = PgRetentionPreview::new(pool);

        assert_eq!(
            simulator
                .reclaimable_content(&[source], 0, 10)
                .await
                .unwrap(),
            RetentionContentSimulation::Omitted
        );
        assert_eq!(
            simulator
                .reclaimable_content(&[source], 10, 1)
                .await
                .unwrap(),
            RetentionContentSimulation::Omitted
        );
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn dry_run_leaves_stream_projection_and_purge_worklist_unchanged() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repository_id = seed_repo(&pool).await;
        let artifact_id =
            seed_artifact(&pool, repository_id, SHARED_PRIMARY, "dry-run-no-mutation").await;
        sqlx::query("UPDATE artifacts SET created_at = '1970-01-01 00:00:00+00' WHERE id = $1")
            .bind(artifact_id)
            .execute(&pool)
            .await
            .expect("make retention age deterministic");
        seed_edge(
            &pool,
            repository_id,
            artifact_id,
            "primary_content",
            SHARED_PRIMARY,
        )
        .await;

        let policy_id = Uuid::new_v4();
        let policy = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
            id: policy_id,
            name: format!("dry-run-policy-{}", policy_id.simple()),
            predicate: PolicyPredicate::AgeExceeds(1),
            scope: RetentionScope::AllRepos,
            created_at: chrono::DateTime::<Utc>::UNIX_EPOCH,
        }])
        .unwrap();
        sqlx::query(
            r#"INSERT INTO retention_policy_projections (
                   policy_id, name, predicate, scope, archived, stream_version,
                   last_evaluated_at, last_matched_count, last_expired_count
               ) VALUES ($1, $2, $3, $4, false, 0, NULL, 0, 0)"#,
        )
        .bind(policy.id)
        .bind(&policy.name)
        .bind(serde_json::to_value(&policy.predicate).unwrap())
        .bind(serde_json::to_value(&policy.scope).unwrap())
        .execute(&pool)
        .await
        .expect("seed retention projection");

        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.expect("event store"));
        let stream_id = StreamId::artifact(artifact_id);
        event_store
            .append(AppendEvents {
                stream_id: stream_id.clone(),
                expected_version: ExpectedVersion::NoStream,
                events: vec![EventToAppend::new(DomainEvent::ArtifactIngested(
                    ArtifactIngested {
                        artifact_id,
                        repository_id,
                        name: "dry-run-no-mutation".into(),
                        version: Some("1.0.0".into()),
                        sha256: SHARED_PRIMARY.parse().unwrap(),
                        size_bytes: 1,
                        source: IngestSource::Proxied,
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
            .expect("seed artifact stream");

        let row = PgRetentionCandidateReader::new(pool.clone())
            .list_candidates(100, None, Utc::now())
            .await
            .expect("candidates")
            .into_iter()
            .find(|row| row.artifact.id == artifact_id)
            .expect("seeded candidate");
        let candidate = RetentionCandidate {
            artifact: row.artifact,
            format: row.format,
            resolved_rescan_interval_hours: row.resolved_rescan_interval_hours,
            keep_rank: row.keep_rank,
            tag_targeted: row.tag_targeted,
        };
        let stream_before = event_store
            .read_stream(&stream_id, ReadFrom::Start, 100)
            .await
            .unwrap();
        let projection_before: (Option<chrono::DateTime<Utc>>, i32, i32) = sqlx::query_as(
            "SELECT last_evaluated_at, last_matched_count, last_expired_count \
               FROM retention_policy_projections WHERE policy_id = $1",
        )
        .bind(policy_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let worklist_before: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifact_purge_worklist WHERE artifact_id = $1",
        )
        .bind(artifact_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let use_case = RetentionUseCase::new(
            Arc::new(EventStorePublisher::without_broadcast(event_store.clone())),
            Arc::new(PgRetentionScanReader::new(pool.clone())),
        );
        let report = use_case
            .evaluate_policies_in_mode(
                Utc::now(),
                std::slice::from_ref(&policy),
                std::slice::from_ref(&candidate),
                RetentionEvaluationMode::DryRun,
            )
            .await
            .expect("dry run");
        assert_eq!(report.matches.len(), 1);

        let stream_after = event_store
            .read_stream(&stream_id, ReadFrom::Start, 100)
            .await
            .unwrap();
        let projection_after: (Option<chrono::DateTime<Utc>>, i32, i32) = sqlx::query_as(
            "SELECT last_evaluated_at, last_matched_count, last_expired_count \
               FROM retention_policy_projections WHERE policy_id = $1",
        )
        .bind(policy_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let worklist_after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifact_purge_worklist WHERE artifact_id = $1",
        )
        .bind(artifact_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(stream_before, stream_after);
        assert_eq!(projection_before, projection_after);
        assert_eq!(worklist_before, worklist_after);

        // Counter-factual: the same fixture, evaluated in execute mode, does
        // append. Without this half the "unchanged" assertions above would
        // also hold for a fixture that simply never matched anything.
        use_case
            .evaluate_policies_in_mode(
                Utc::now(),
                &[policy],
                std::slice::from_ref(&candidate),
                RetentionEvaluationMode::Execute,
            )
            .await
            .expect("execute");
        let stream_executed = event_store
            .read_stream(&stream_id, ReadFrom::Start, 100)
            .await
            .unwrap();
        assert_eq!(stream_executed.len(), stream_after.len() + 1);
        assert!(matches!(
            stream_executed.last().unwrap().event,
            DomainEvent::ArtifactExpired(_)
        ));
        // Only purge writes the worklist; evaluation never does, in either mode.
        let worklist_executed: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifact_purge_worklist WHERE artifact_id = $1",
        )
        .bind(artifact_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(worklist_executed, worklist_before);
    }
}
