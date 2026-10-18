//! PostgreSQL implementation of the event-aggregate → repository
//! resolution the events-read gate and the subscription filter share.
//!
//! One statement answers both aggregate kinds. The two legs are
//! primary-key joins against `artifacts` / `artifact_groups`, unioned
//! with a `kind` discriminator so the caller can split the rows back
//! apart without a second round trip.
//!
//! # Why the id sets are CTEs and not `= ANY($1)`
//!
//! The membership test reads naturally as `WHERE id = ANY($1::uuid[])`,
//! and that form is a latency trap under a prepared statement. Postgres
//! folds bound parameters into constants only while it is building
//! **custom** plans; once the statement flips to a **generic** plan
//! (which it does from the sixth execution on a pooled connection, and
//! connections in a server pool live for days), `$1` stays a `Param`, the
//! array can no longer be hashed, and the filter degrades to a linear
//! scan of the whole id array for every candidate row — with nothing in
//! the query, the data or the configuration having changed. The project
//! has measured the cliff on its own corpus at 1.3 s custom against
//! 64.2 s generic (see
//! [`crate::retention_preview`], whose survivor probe is the same
//! rewrite for the same reason).
//!
//! Unnesting the array into a CTE expresses the identical set — the CTE
//! *is* that array — and plans as a join under both plan types, so the
//! cliff disappears. Do not "simplify" it back to `= ANY`.
//!
//! # Identity, not liveness
//!
//! Neither leg filters on `deleted_at` / `is_deleted`, and that is
//! load-bearing rather than an omission: purge retires an artifact's
//! projection row instead of removing it, and `ArtifactPurged` /
//! `ArtifactExpired` are exactly the events whose reader still has to be
//! gated against the repository that owned the artifact. A liveness
//! filter here would resolve a retired artifact to nothing, and the
//! consumer's fail-closed path would then hide a repository's own
//! retention history from its own readers.
//!
//! A row that genuinely does not exist (the repository was deleted,
//! cascading its artifacts away) is reported by omission — the id has no
//! entry in the result — and the consumer fails closed on it.

use std::collections::HashMap;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::event_repository_resolver::{
    EventAggregateRepositories, EventRepositoryResolver,
};

use crate::{map_sqlx_error, BoxFuture};

/// Row discriminator for the unioned legs. Must match the literals in
/// the statement below.
const ARTIFACT_KIND: &str = "artifact";
const ARTIFACT_GROUP_KIND: &str = "artifact_group";

/// Read-only Postgres resolver for event-aggregate repository lookups.
pub struct PgEventRepositoryResolver {
    pool: PgPool,
}

impl PgEventRepositoryResolver {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl EventRepositoryResolver for PgEventRepositoryResolver {
    fn resolve_event_aggregates<'a>(
        &'a self,
        artifact_ids: &'a [Uuid],
        artifact_group_ids: &'a [Uuid],
    ) -> BoxFuture<'a, DomainResult<EventAggregateRepositories>> {
        Box::pin(async move {
            // A page whose every event carries its repository in the
            // payload asks about nothing; do not spend a round trip
            // proving it.
            if artifact_ids.is_empty() && artifact_group_ids.is_empty() {
                return Ok(EventAggregateRepositories::default());
            }

            let rows = sqlx::query(
                r#"
                WITH wanted_artifacts AS (
                    SELECT unnest($1::uuid[]) AS id
                ),
                wanted_groups AS (
                    SELECT unnest($2::uuid[]) AS id
                )
                SELECT 'artifact' AS kind, a.id AS aggregate_id, a.repository_id
                  FROM artifacts a
                  JOIN wanted_artifacts w ON w.id = a.id
                UNION ALL
                SELECT 'artifact_group' AS kind, g.id AS aggregate_id, g.repository_id
                  FROM artifact_groups g
                  JOIN wanted_groups w ON w.id = g.id
                "#,
            )
            .bind(artifact_ids)
            .bind(artifact_group_ids)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "event_repository_resolver", "resolve"))?;

            let mut artifacts: HashMap<Uuid, Uuid> = HashMap::with_capacity(artifact_ids.len());
            let mut groups: HashMap<Uuid, Uuid> = HashMap::with_capacity(artifact_group_ids.len());
            for row in rows {
                let kind: String = row.try_get("kind").map_err(|e| decode_error(&e))?;
                let aggregate_id: Uuid =
                    row.try_get("aggregate_id").map_err(|e| decode_error(&e))?;
                let repository_id: Uuid =
                    row.try_get("repository_id").map_err(|e| decode_error(&e))?;
                match kind.as_str() {
                    ARTIFACT_KIND => {
                        artifacts.insert(aggregate_id, repository_id);
                    }
                    ARTIFACT_GROUP_KIND => {
                        groups.insert(aggregate_id, repository_id);
                    }
                    // The discriminator is a literal in the statement
                    // above, so this is unreachable short of someone
                    // editing one half of the pair. Refuse rather than
                    // drop the row: a silently dropped row resolves to
                    // "unknown aggregate", which fails a legitimate
                    // reader closed with no signal anywhere.
                    other => {
                        return Err(DomainError::Invariant(format!(
                            "event_repository_resolver: unknown aggregate kind {other:?}"
                        )))
                    }
                }
            }
            Ok(EventAggregateRepositories {
                artifacts,
                artifact_groups: groups,
            })
        })
    }
}

fn decode_error(e: &sqlx::Error) -> DomainError {
    DomainError::Invariant(format!("event_repository_resolver row decode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use serial_test::serial;

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;
        Some(pool)
    }

    async fn seed_repo(pool: &PgPool) -> Uuid {
        let key = format!("repo-{}", Uuid::new_v4());
        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO repositories (
                   key, name, format, repo_type, storage_backend, storage_path,
                   replication_priority
               ) VALUES (
                   $1, $1, 'generic', 'hosted', 'filesystem', $2, 'local_only'
               ) RETURNING id"#,
        )
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .fetch_one(pool)
        .await
        .expect("seed repository");
        id
    }

    async fn seed_artifact(pool: &PgPool, repo: Uuid, deleted: bool) -> Uuid {
        let name = format!("pkg-{}", Uuid::new_v4());
        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO artifacts (
                   repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   quarantine_status, deleted_at
               ) VALUES (
                   $1, $2, $2, '1.0.0', $3,
                   1, $4, 'application/octet-stream', $3,
                   'released', CASE WHEN $5 THEN now() ELSE NULL END
               ) RETURNING id"#,
        )
        .bind(repo)
        .bind(&name)
        .bind(format!("{name}/1.0.0/{name}.tar.gz"))
        .bind("a".repeat(64))
        .bind(deleted)
        .fetch_one(pool)
        .await
        .expect("seed artifact");
        id
    }

    async fn seed_group(pool: &PgPool, repo: Uuid) -> Uuid {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO artifact_groups (repository_id, coords_json, primary_role) \
             VALUES ($1, $2::jsonb, 'pom') RETURNING id",
        )
        .bind(repo)
        .bind(format!(r#"{{"name":"g-{}"}}"#, Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .expect("seed artifact group");
        id
    }

    /// Both aggregate kinds resolve, in one call, and an id with no row
    /// is absent rather than mapped to anything.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn resolves_both_kinds_and_omits_what_does_not_exist() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_a = seed_repo(&pool).await;
        let repo_b = seed_repo(&pool).await;
        let artifact_a = seed_artifact(&pool, repo_a, false).await;
        let artifact_b = seed_artifact(&pool, repo_b, false).await;
        let group = seed_group(&pool, repo_b).await;
        let absent_artifact = Uuid::new_v4();
        let absent_group = Uuid::new_v4();

        let resolved = PgEventRepositoryResolver::new(pool)
            .resolve_event_aggregates(
                &[artifact_a, artifact_b, absent_artifact],
                &[group, absent_group],
            )
            .await
            .expect("resolution must succeed");

        assert_eq!(resolved.artifacts.get(&artifact_a), Some(&repo_a));
        assert_eq!(resolved.artifacts.get(&artifact_b), Some(&repo_b));
        assert_eq!(resolved.artifacts.get(&absent_artifact), None);
        assert_eq!(resolved.artifact_groups.get(&group), Some(&repo_b));
        assert_eq!(resolved.artifact_groups.get(&absent_group), None);
    }

    /// A retired artifact still answers for its repository. Purge sets
    /// `deleted_at` rather than removing the row, and `ArtifactPurged` /
    /// `ArtifactExpired` are precisely the events whose reader must be
    /// gated against that repository — a liveness filter here would
    /// hide a repository's own retention history from its own readers.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_retired_artifact_still_resolves() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let retired = seed_artifact(&pool, repo, true).await;

        let resolved = PgEventRepositoryResolver::new(pool)
            .resolve_event_aggregates(&[retired], &[])
            .await
            .expect("resolution must succeed");

        assert_eq!(
            resolved.artifacts.get(&retired),
            Some(&repo),
            "a retired artifact resolves by identity; liveness is not this port's question"
        );
    }

    /// An empty ask must not reach the database at all — the read hot
    /// path's common case is a page that carries its repositories.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn an_empty_ask_is_answered_without_a_round_trip() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        // Close the pool first: a statement issued against it would
        // error, so an `Ok` here proves no statement was issued.
        pool.close().await;
        let resolved = PgEventRepositoryResolver::new(pool)
            .resolve_event_aggregates(&[], &[])
            .await
            .expect("an empty ask must short-circuit before touching the pool");
        assert!(resolved.artifacts.is_empty());
        assert!(resolved.artifact_groups.is_empty());
    }

    /// Plan-stability guard. The statement's membership test must stay a
    /// join against an unnested CTE; `= ANY($n)` on a pooled prepared
    /// statement flips to a row-by-row scan on the sixth execution (1.3 s
    /// custom plan against 64.2 s generic, measured on this project's
    /// corpus). A source scan is the only thing that catches the rewrite,
    /// because the `= ANY` form is correct — it is only slow, and only
    /// after the plan flips.
    #[test]
    fn the_membership_test_is_a_join_not_an_array_predicate() {
        let source = include_str!("event_repository_resolver.rs");
        // Skip this file's own prose, which names the rejected form.
        let statement = source
            .split("WITH wanted_artifacts AS (")
            .nth(1)
            .expect("the statement must still be in this file");
        let statement = statement
            .split("\"#,")
            .next()
            .expect("the statement must be a terminated raw string");
        assert!(
            !statement.contains("= ANY"),
            "the membership test must be a join against the unnested CTE, never `= ANY`"
        );
        assert!(
            statement.contains("JOIN wanted_artifacts w ON w.id = a.id"),
            "the artifact leg must join the CTE"
        );
        assert!(
            statement.contains("JOIN wanted_groups w ON w.id = g.id"),
            "the artifact-group leg must join the CTE"
        );
        assert!(
            !statement.contains("deleted_at") && !statement.contains("is_deleted"),
            "resolution is by identity; a liveness filter would hide a retired \
             artifact's events from its own repository's readers"
        );
    }
}
