//! PostgreSQL write-side adapter for `artifact_groups` +
//! `artifact_group_members` + their event stream.
//!
//! Implements [`ArtifactGroupLifecyclePort`]. Wraps the projection-row
//! writes and the event append in a single transaction via
//! [`PgEventStore::append_in_tx`] so neither side can land without the
//! other.
//!
//! # Three load-bearing rules (see port docstring)
//!
//! 1. **The adapter never mutates `DomainEvent` payloads.** The caller
//!    hands us an [`AppendEvents`]; we either append it verbatim or
//!    roll back the whole transaction. There is no `serde_json`
//!    round-trip of event payloads inside this file; there is no
//!    `match` arm that opens a `DomainEvent::ArtifactGroup*` variant to
//!    patch `group_id`.
//!
//! 2. **Concurrent-create races surface as
//!    [`GroupCommitOutcome::GroupAlreadyExists`].** `INSERT ...
//!    ON CONFLICT (repository_id, coords_json) DO NOTHING RETURNING
//!    id` produces no row on a race; the adapter `SELECT`s the
//!    winner's id, drops the uncommitted transaction (implicit
//!    rollback on drop), and returns the typed outcome. The use case
//!    retries with freshly-built events against the observed id —
//!    this adapter never sees patched payloads.
//!
//! 3. **Primary-role races are unrecoverable conflicts.** When
//!    `GroupMemberCommit::primary_role_assigned.is_some()`, the
//!    adapter runs `UPDATE artifact_groups SET primary_role = $1
//!    WHERE id = $2 AND primary_role = ''`. Zero rows affected → the
//!    whole transaction rolls back and the adapter returns
//!    `DomainError::Conflict`. Member-add for the losing call does
//!    NOT land; the caller chose a privileged operation and needs to
//!    know it didn't stick.
//!
//! See design doc §2.6a, §2.9–§2.11.

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::artifact_group_lifecycle::{
    ArtifactGroupLifecyclePort, GroupCommitOutcome, GroupMemberCommit,
};
use hort_domain::ports::event_store::AppendEvents;
use hort_domain::ports::BoxFuture;

use crate::artifact_group_repo::coords_to_canonical_json;
use crate::event_store::PgEventStore;

/// PostgreSQL implementation of [`ArtifactGroupLifecyclePort`].
pub struct PgArtifactGroupLifecycle {
    event_store: Arc<PgEventStore>,
}

impl PgArtifactGroupLifecycle {
    /// Construct the adapter. The transactional path goes through
    /// `event_store.begin_unit_of_work()`; no separate pool handle is
    /// needed.
    pub fn new(event_store: Arc<PgEventStore>) -> Self {
        Self { event_store }
    }
}

impl ArtifactGroupLifecyclePort for PgArtifactGroupLifecycle {
    fn commit_member_added(
        &self,
        change: GroupMemberCommit,
        batch: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<GroupCommitOutcome>> {
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;

            // -----------------------------------------------------------
            // Step 1 — group row: insert-or-observe-the-winner.
            // -----------------------------------------------------------
            let target_group_id = if let Some(new_group) = change.new_group.as_ref() {
                let canonical = coords_to_canonical_json(&new_group.coords)?;
                // `ON CONFLICT ... DO NOTHING` + `RETURNING id` collapses
                // the "did we win the race?" question into a single
                // round-trip. If the concurrent racer won, `RETURNING`
                // yields zero rows and we must observe their id.
                let inserted: Option<Uuid> = sqlx::query_scalar(
                    r#"INSERT INTO artifact_groups (
                           id, repository_id, coords_json, primary_role,
                           created_at, updated_at
                       ) VALUES ($1, $2, $3, $4, NOW(), NOW())
                       ON CONFLICT (repository_id, coords_json) DO NOTHING
                       RETURNING id"#,
                )
                .bind(new_group.id)
                .bind(new_group.repository_id)
                .bind(&canonical)
                .bind(&new_group.primary_role)
                .fetch_optional(uow.conn())
                .await
                .map_err(|e| {
                    DomainError::Invariant(format!("artifact_groups INSERT failed: {e}"))
                })?;

                match inserted {
                    Some(id) => id,
                    None => {
                        // Concurrent writer won the race. Look up their
                        // id so the use case's retry has something to
                        // rebuild events against. Drop `uow` on return
                        // → Postgres rolls the transaction back
                        // implicitly; no events, no member row, no
                        // stale state committed.
                        let existing_id: Uuid = sqlx::query_scalar(
                            r#"SELECT id FROM artifact_groups
                               WHERE repository_id = $1 AND coords_json = $2"#,
                        )
                        .bind(new_group.repository_id)
                        .bind(&canonical)
                        .fetch_one(uow.conn())
                        .await
                        .map_err(|e| {
                            DomainError::Invariant(format!(
                                "artifact_groups lookup after ON CONFLICT race failed: {e}"
                            ))
                        })?;
                        tracing::warn!(
                            %existing_id,
                            "concurrent group creation observed; rolling back and returning GroupAlreadyExists"
                        );
                        // `uow` drops here without a commit call,
                        // implicitly rolling back. Explicit drop for
                        // clarity.
                        drop(uow);
                        return Ok(GroupCommitOutcome::GroupAlreadyExists { existing_id });
                    }
                }
            } else {
                // No new_group — caller asserts the group already
                // exists. Use the batch's stream id as the group id;
                // this is the contract between the use case and the
                // adapter (the use case always keys the batch on the
                // group it wants to append to).
                batch.stream_id.entity_id
            };

            // -----------------------------------------------------------
            // Step 2 — primary-role assignment (§2.10 case 2).
            // -----------------------------------------------------------
            // Race-safe conditional update: only fills a previously-
            // empty slot. `rows_affected = 0` means another writer got
            // there first; the WHOLE transaction must roll back so
            // the member add for this call does not land.
            if let Some(primary_role) = change.primary_role_assigned.as_deref() {
                let rows_affected = sqlx::query(
                    r#"UPDATE artifact_groups
                       SET primary_role = $1, updated_at = NOW()
                       WHERE id = $2 AND primary_role = ''"#,
                )
                .bind(primary_role)
                .bind(target_group_id)
                .execute(uow.conn())
                .await
                .map_err(|e| {
                    DomainError::Invariant(format!(
                        "artifact_groups primary_role UPDATE failed: {e}"
                    ))
                })?
                .rows_affected();
                if rows_affected == 0 {
                    // Loser of the primary-assign race. Drop `uow`
                    // (rollback) and surface Conflict — the caller
                    // chose a privileged operation and must re-decide.
                    drop(uow);
                    return Err(DomainError::Conflict(format!(
                        "primary_role already assigned on group {target_group_id} (race lost)"
                    )));
                }
            }

            // -----------------------------------------------------------
            // Step 3 — member row.
            // -----------------------------------------------------------
            // `ON CONFLICT DO NOTHING RETURNING role` — if the
            // (group_id, artifact_id) already exists, we observe the
            // stored role in the same round-trip (via a follow-up
            // SELECT) and decide whether this is an idempotent re-add
            // or a role conflict.
            let inserted_rows = sqlx::query(
                r#"INSERT INTO artifact_group_members (
                       group_id, role, artifact_id, added_at
                   ) VALUES ($1, $2, $3, NOW())
                   ON CONFLICT (group_id, artifact_id) DO NOTHING"#,
            )
            .bind(target_group_id)
            .bind(&change.member.role)
            .bind(change.member.artifact_id)
            .execute(uow.conn())
            .await
            .map_err(|e| {
                DomainError::Invariant(format!("artifact_group_members INSERT failed: {e}"))
            })?
            .rows_affected();

            if inserted_rows == 0 {
                // Existing row. Inspect `role` to decide idempotent
                // vs conflict. If same role → no event, commit the
                // transaction (to release the member-row lock), and
                // return Committed. If different role → roll back
                // and surface Conflict.
                let existing_role: String = sqlx::query_scalar(
                    r#"SELECT role FROM artifact_group_members
                       WHERE group_id = $1 AND artifact_id = $2"#,
                )
                .bind(target_group_id)
                .bind(change.member.artifact_id)
                .fetch_one(uow.conn())
                .await
                .map_err(|e| {
                    DomainError::Invariant(format!(
                        "artifact_group_members lookup after ON CONFLICT failed: {e}"
                    ))
                })?;
                if existing_role == change.member.role {
                    tracing::debug!(
                        group_id = %target_group_id,
                        artifact_id = %change.member.artifact_id,
                        role = %existing_role,
                        "idempotent same-role re-add; no event emitted"
                    );
                    // Commit releases the row lock from the INSERT
                    // attempt; nothing else was written, so the txn
                    // is semantically a no-op.
                    uow.commit().await?;
                    return Ok(GroupCommitOutcome::Committed);
                }
                drop(uow);
                return Err(DomainError::Conflict(format!(
                    "artifact {artifact_id} already belongs to group {group_id} with role `{existing}`, cannot re-add with role `{requested}`",
                    artifact_id = change.member.artifact_id,
                    group_id = target_group_id,
                    existing = existing_role,
                    requested = change.member.role,
                )));
            }

            // -----------------------------------------------------------
            // Step 4 — append events verbatim.
            // -----------------------------------------------------------
            // The adapter MUST NOT touch `batch.events`. Hand the
            // batch to `PgEventStore::append_in_tx` unmodified.
            self.event_store.append_in_tx(&mut uow, batch).await?;

            uow.commit().await?;
            Ok(GroupCommitOutcome::Committed)
        })
    }

    fn commit_member_removed(
        &self,
        group_id: Uuid,
        artifact_id: Uuid,
        batch: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;

            // `RETURNING role` lets us decide whether the row existed
            // in a single round-trip. Zero rows → NotFound, no event
            // appended, transaction rolled back on drop.
            let deleted: Option<String> = sqlx::query_scalar(
                r#"DELETE FROM artifact_group_members
                   WHERE group_id = $1 AND artifact_id = $2
                   RETURNING role"#,
            )
            .bind(group_id)
            .bind(artifact_id)
            .fetch_optional(uow.conn())
            .await
            .map_err(|e| {
                DomainError::Invariant(format!("artifact_group_members DELETE failed: {e}"))
            })?;

            if deleted.is_none() {
                drop(uow);
                return Err(DomainError::NotFound {
                    entity: "ArtifactGroupMember",
                    id: format!("{group_id}/{artifact_id}"),
                });
            }

            self.event_store.append_in_tx(&mut uow, batch).await?;

            uow.commit().await?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Compile-time proof the adapter implements the port. Runtime
    /// invocation is covered by the integration tests below.
    #[test]
    fn pg_artifact_group_lifecycle_implements_port() {
        fn _assert_port<T: ArtifactGroupLifecyclePort>() {}
        _assert_port::<PgArtifactGroupLifecycle>();
    }

    // ---------------------------------------------------------------
    // DB-backed integration tests. Skipped (noisy "pass") when
    // `DATABASE_URL` is unset — mirrors `artifact_group_repo.rs`.
    // ---------------------------------------------------------------

    use chrono::Utc;
    use hort_domain::entities::artifact_group::{ArtifactGroup, ArtifactGroupMember};
    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::events::{
        Actor, ApiActor, ArtifactGroupInitiated, ArtifactGroupMemberAdded,
        ArtifactGroupMemberRemoved, DomainEvent, StreamId,
    };
    use hort_domain::ports::event_store::{EventToAppend, ExpectedVersion};
    use hort_domain::types::ArtifactCoords;
    use sqlx::PgPool;
    use std::env;

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    async fn seed_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("it-agwrite-{}", id.simple());
        sqlx::query(
            r#"INSERT INTO repositories (
                   id, key, name, format, repo_type, storage_backend, storage_path,
                   replication_priority
               ) VALUES (
                   $1, $2, $3,
                   'generic'::repository_format,
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
        .expect("seed repo insert");
        id
    }

    async fn cleanup_repo(pool: &PgPool, repo: Uuid) {
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(pool)
            .await;
    }

    async fn seed_artifact(pool: &PgPool, repo: Uuid, path: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key
               ) VALUES (
                   $1, $2, $3, $3, '1.0.0', $4,
                   0,
                   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                   'application/octet-stream', $4
               )"#,
        )
        .bind(id)
        .bind(repo)
        .bind(path)
        .bind(path)
        .execute(pool)
        .await
        .expect("seed artifact insert");
        id
    }

    fn maven_coords(name: &str, version: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.into(),
            name_as_published: name.into(),
            version: Some(version.into()),
            path: String::new(),
            format: RepositoryFormat::Maven,
            metadata: serde_json::Value::Null,
        }
    }

    fn make_group(repo: Uuid, coords: &ArtifactCoords, primary_role: &str) -> ArtifactGroup {
        ArtifactGroup {
            id: Uuid::new_v4(),
            repository_id: repo,
            coords: coords.clone(),
            primary_role: primary_role.to_string(),
            members: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn build_first_placement_batch(
        group_id: Uuid,
        repo: Uuid,
        coords: &ArtifactCoords,
        role: &str,
        artifact_id: Uuid,
        primary_role: &str,
    ) -> AppendEvents {
        AppendEvents {
            stream_id: StreamId::artifact_group(group_id),
            expected_version: ExpectedVersion::NoStream,
            events: vec![
                EventToAppend::new(DomainEvent::ArtifactGroupInitiated(
                    ArtifactGroupInitiated {
                        group_id,
                        repository_id: repo,
                        coords: coords.clone(),
                        primary_role: primary_role.into(),
                    },
                )),
                EventToAppend::new(DomainEvent::ArtifactGroupMemberAdded(
                    ArtifactGroupMemberAdded {
                        group_id,
                        role: role.into(),
                        artifact_id,
                    },
                )),
            ],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
        }
    }

    fn build_append_batch(group_id: Uuid, role: &str, artifact_id: Uuid) -> AppendEvents {
        AppendEvents {
            stream_id: StreamId::artifact_group(group_id),
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(DomainEvent::ArtifactGroupMemberAdded(
                ArtifactGroupMemberAdded {
                    group_id,
                    role: role.into(),
                    artifact_id,
                },
            ))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
        }
    }

    /// Transactional abort: feed `commit_member_added` an event whose
    /// per-field validation fails. The adapter's `append_in_tx` must
    /// propagate the error; the transaction rolls back; neither the
    /// projection rows nor the event row lands.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn transactional_abort_leaves_no_state() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        let adapter = PgArtifactGroupLifecycle::new(event_store.clone());

        let coords = maven_coords("com.example:bad", "1.0.0");
        let artifact = seed_artifact(&pool, repo, "bad-1.0.0.jar").await;
        let new_group = make_group(repo, &coords, "jar");
        let group_id = new_group.id;

        // Role exceeds the MAX_ROLE_LEN = 128 cap → per-field
        // validation fails inside `append_in_tx` → transaction rolls
        // back before any projection row survives.
        let bad_role = "x".repeat(200);
        let change = GroupMemberCommit {
            new_group: Some(new_group.clone()),
            member: ArtifactGroupMember {
                role: bad_role.clone(),
                artifact_id: artifact,
                added_at: Utc::now(),
            },
            primary_role_assigned: None,
        };
        let bad_batch = AppendEvents {
            stream_id: StreamId::artifact_group(group_id),
            expected_version: ExpectedVersion::NoStream,
            events: vec![
                EventToAppend::new(DomainEvent::ArtifactGroupInitiated(
                    ArtifactGroupInitiated {
                        group_id,
                        repository_id: repo,
                        coords: coords.clone(),
                        primary_role: "jar".into(),
                    },
                )),
                EventToAppend::new(DomainEvent::ArtifactGroupMemberAdded(
                    ArtifactGroupMemberAdded {
                        group_id,
                        role: bad_role,
                        artifact_id: artifact,
                    },
                )),
            ],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
        };

        let err = adapter
            .commit_member_added(change, bad_batch)
            .await
            .expect_err("oversized role must fail validation");
        assert!(
            matches!(err, DomainError::Validation(_)),
            "expected Validation, got: {err}"
        );

        let group_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifact_groups WHERE id = $1")
                .bind(group_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(group_count, 0, "projection group row must not commit");
        let member_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifact_group_members WHERE group_id = $1")
                .bind(group_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(member_count, 0, "projection member row must not commit");
        let event_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE stream_id = $1")
                .bind(format!("artifact_group-{group_id}"))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(event_count, 0, "event row must not commit");

        cleanup_repo(&pool, repo).await;
    }

    /// Concurrent-create race: two callers build first-placement
    /// batches with the SAME (repo, coords) but DIFFERENT tentative
    /// group ids. Exactly ONE `artifact_groups` row lands, exactly
    /// ONE `ArtifactGroupInitiated` event lands, the loser's stale
    /// tentative id is never materialised anywhere. The loser gets
    /// `Ok(GroupAlreadyExists { existing_id })` and the caller
    /// (the use case) retries — this test simulates the retry by
    /// making a second call with the observed id.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn concurrent_create_race_surfaces_group_already_exists() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        let adapter = Arc::new(PgArtifactGroupLifecycle::new(event_store.clone()));

        let coords = maven_coords("com.example:race", "1.0.0");
        let art_a = seed_artifact(&pool, repo, "race-a.jar").await;
        let art_b = seed_artifact(&pool, repo, "race-b.jar").await;
        let group_a = make_group(repo, &coords, "jar");
        let group_b = make_group(repo, &coords, "jar");
        let id_a = group_a.id;
        let id_b = group_b.id;
        assert_ne!(id_a, id_b, "racers mint distinct tentative ids");

        // Sequential execution — emulates two concurrent callers with
        // one beating the other to the INSERT. The adapter's ON
        // CONFLICT short-circuits the loser in the SAME way it would
        // under true concurrent execution.
        let a = adapter.clone();
        let b = adapter.clone();
        let coords_a = coords.clone();
        let coords_b = coords.clone();

        let change_a = GroupMemberCommit {
            new_group: Some(group_a.clone()),
            member: ArtifactGroupMember {
                role: "jar".into(),
                artifact_id: art_a,
                added_at: Utc::now(),
            },
            primary_role_assigned: None,
        };
        let change_b = GroupMemberCommit {
            new_group: Some(group_b.clone()),
            member: ArtifactGroupMember {
                role: "jar".into(),
                artifact_id: art_b,
                added_at: Utc::now(),
            },
            primary_role_assigned: None,
        };
        let batch_a = build_first_placement_batch(id_a, repo, &coords_a, "jar", art_a, "jar");
        let batch_b = build_first_placement_batch(id_b, repo, &coords_b, "jar", art_b, "jar");

        let outcome_a = a
            .commit_member_added(change_a, batch_a)
            .await
            .expect("first caller commits");
        let outcome_b = b
            .commit_member_added(change_b, batch_b)
            .await
            .expect("second caller returns typed outcome");

        assert!(matches!(outcome_a, GroupCommitOutcome::Committed));
        let winner_id = match outcome_b {
            GroupCommitOutcome::GroupAlreadyExists { existing_id } => existing_id,
            GroupCommitOutcome::Committed => panic!("loser should see AlreadyExists"),
        };
        assert_eq!(winner_id, id_a, "loser observes the winner's id");

        // Simulate the use case's retry: rebuild a fresh batch
        // against the winner's id.
        let retry_change = GroupMemberCommit {
            new_group: None,
            member: ArtifactGroupMember {
                role: "pom".into(),
                artifact_id: art_b,
                added_at: Utc::now(),
            },
            primary_role_assigned: None,
        };
        let retry_batch = build_append_batch(winner_id, "pom", art_b);
        let outcome_retry = adapter
            .commit_member_added(retry_change, retry_batch)
            .await
            .expect("retry succeeds");
        assert!(matches!(outcome_retry, GroupCommitOutcome::Committed));

        // Post-state assertions.
        let group_row_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifact_groups WHERE repository_id = $1 AND coords_json = $2",
        )
        .bind(repo)
        .bind(coords_to_canonical_json(&coords).unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(group_row_count, 1, "exactly one artifact_groups row");

        // Scope all assertions to the winner's stream so stale state
        // from prior (failed) runs of the same test can't skew counts.
        let winner_stream = format!("artifact_group-{winner_id}");

        let initiated_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events \
             WHERE stream_id = $1 AND event_type = 'ArtifactGroupInitiated'",
        )
        .bind(&winner_stream)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            initiated_events, 1,
            "exactly one Initiated event (loser rolled back)"
        );

        let member_added_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events \
             WHERE stream_id = $1 AND event_type = 'ArtifactGroupMemberAdded'",
        )
        .bind(&winner_stream)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            member_added_events, 2,
            "two MemberAdded events (winner's first + loser's retry)"
        );

        // Loser's stale tentative id must not appear anywhere in
        // `events.event_data` — the adapter never mutates payloads,
        // and the rolled-back batch was discarded. Scoped by
        // stream_category so older runs in other categories can't false-match.
        let stale_id_hits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events \
             WHERE stream_category = 'artifact_group' AND event_data::text LIKE $1",
        )
        .bind(format!("%{id_b}%"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            stale_id_hits, 0,
            "no event payload references the loser's stale tentative id"
        );

        // All MemberAdded events on the winner's stream carry the
        // winner's id inside their `data.group_id` payload field.
        // (`serialize_event_data` wraps payloads as
        // `{"type": ..., "data": {...fields...}}`, so `group_id` lives
        // under `data`, not at the top level.)
        let winner_member_adds: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events \
             WHERE stream_id = $1 \
               AND event_type = 'ArtifactGroupMemberAdded' \
               AND event_data->'data'->>'group_id' = $2",
        )
        .bind(&winner_stream)
        .bind(winner_id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            winner_member_adds, 2,
            "both MemberAdded payloads reference the committed group id"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// Primary-role-assign race: seed a group with `primary_role =
    /// ''`, drive two `commit_member_added` calls that both set
    /// `primary_role_assigned = Some(role)`. Exactly ONE wins the
    /// conditional UPDATE; the loser's entire transaction rolls back
    /// — no member row, no events, `DomainError::Conflict`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn concurrent_primary_role_assign_surfaces_conflict() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        let adapter = Arc::new(PgArtifactGroupLifecycle::new(event_store.clone()));

        let coords = maven_coords("com.example:pra", "1.0.0");
        // Seed a group with primary_role = '' directly.
        let group_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO artifact_groups (id, repository_id, coords_json, primary_role)
               VALUES ($1, $2, $3, '')"#,
        )
        .bind(group_id)
        .bind(repo)
        .bind(coords_to_canonical_json(&coords).unwrap())
        .execute(&pool)
        .await
        .expect("seed group row");

        let art_a = seed_artifact(&pool, repo, "pra-a.jar").await;
        let art_b = seed_artifact(&pool, repo, "pra-b.pom").await;

        fn build_primary_batch(group_id: Uuid, role: &str, artifact_id: Uuid) -> AppendEvents {
            AppendEvents {
                stream_id: StreamId::artifact_group(group_id),
                expected_version: ExpectedVersion::Any,
                events: vec![
                    EventToAppend::new(DomainEvent::ArtifactGroupMemberAdded(
                        ArtifactGroupMemberAdded {
                            group_id,
                            role: role.into(),
                            artifact_id,
                        },
                    )),
                    EventToAppend::new(DomainEvent::ArtifactGroupPrimaryRoleAssigned(
                        hort_domain::events::ArtifactGroupPrimaryRoleAssigned {
                            group_id,
                            primary_role: role.into(),
                        },
                    )),
                ],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: Actor::Api(ApiActor {
                    user_id: Uuid::new_v4(),
                }),
            }
        }

        let change_a = GroupMemberCommit {
            new_group: None,
            member: ArtifactGroupMember {
                role: "jar".into(),
                artifact_id: art_a,
                added_at: Utc::now(),
            },
            primary_role_assigned: Some("jar".into()),
        };
        let change_b = GroupMemberCommit {
            new_group: None,
            member: ArtifactGroupMember {
                role: "pom".into(),
                artifact_id: art_b,
                added_at: Utc::now(),
            },
            primary_role_assigned: Some("pom".into()),
        };
        let batch_a = build_primary_batch(group_id, "jar", art_a);
        let batch_b = build_primary_batch(group_id, "pom", art_b);

        let res_a = adapter.commit_member_added(change_a, batch_a).await;
        let res_b = adapter.commit_member_added(change_b, batch_b).await;

        // Exactly one success.
        let ok_count = [res_a.is_ok(), res_b.is_ok()]
            .iter()
            .filter(|x| **x)
            .count();
        assert_eq!(ok_count, 1, "one winner of the primary-role race");
        let conflict_count = [&res_a, &res_b]
            .iter()
            .filter(|r| matches!(r, Err(DomainError::Conflict(_))))
            .count();
        assert_eq!(conflict_count, 1, "one loser surfaces Conflict");

        // Post-state: primary_role set exactly once.
        let primary: String =
            sqlx::query_scalar("SELECT primary_role FROM artifact_groups WHERE id = $1")
                .bind(group_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            primary == "jar" || primary == "pom",
            "primary_role pinned to one of the racers, got: {primary}"
        );

        // Exactly one PrimaryRoleAssigned event landed.
        let assigned: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events \
             WHERE stream_id = $1 AND event_type = 'ArtifactGroupPrimaryRoleAssigned'",
        )
        .bind(format!("artifact_group-{group_id}"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(assigned, 1);

        // Exactly one MemberAdded event landed (loser's rolled back).
        let added: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events \
             WHERE stream_id = $1 AND event_type = 'ArtifactGroupMemberAdded'",
        )
        .bind(format!("artifact_group-{group_id}"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(added, 1, "loser's member-add was rolled back too");

        // Exactly one member row on the projection side.
        let member_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifact_group_members WHERE group_id = $1")
                .bind(group_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(member_rows, 1);

        cleanup_repo(&pool, repo).await;
    }

    /// Sentinel test: the adapter does NOT mutate event payloads.
    /// We write a first-placement batch with a distinctive marker
    /// string inside `ArtifactGroupInitiated.coords.name` and a
    /// distinctive sentinel in `ArtifactGroupMemberRemoved.reason`
    /// (via a follow-up remove call). After commit, the sentinel
    /// round-trips through `events.event_data` verbatim.
    ///
    /// We ALSO verify the negative half: on a `GroupAlreadyExists`
    /// return from a concurrent-create race, the loser's sentinel is
    /// absent — the adapter rolled the whole transaction back, so
    /// the payload never touched the event log.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn adapter_never_mutates_event_payloads_sentinel() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        let adapter = PgArtifactGroupLifecycle::new(event_store.clone());

        // Positive half — sentinel survives a commit.
        const SENTINEL_NAME: &str = "com.example:ADAPTER_SENTINEL_DO_NOT_MUTATE";
        const SENTINEL_REASON: &str = "REMOVE_REASON_SENTINEL_XYZ42";
        let coords = maven_coords(SENTINEL_NAME, "1.0.0");
        let artifact = seed_artifact(&pool, repo, "sentinel.jar").await;
        let group = make_group(repo, &coords, "jar");
        let group_id = group.id;
        let change = GroupMemberCommit {
            new_group: Some(group.clone()),
            member: ArtifactGroupMember {
                role: "jar".into(),
                artifact_id: artifact,
                added_at: Utc::now(),
            },
            primary_role_assigned: None,
        };
        let batch = build_first_placement_batch(group_id, repo, &coords, "jar", artifact, "jar");
        let outcome = adapter.commit_member_added(change, batch).await.unwrap();
        assert!(matches!(outcome, GroupCommitOutcome::Committed));

        // Sentinel in the Initiated event's coords.name — verbatim.
        // `serialize_event_data` nests payload fields under `data`, so
        // the path is `event_data->'data'->'coords'->>'name'`.
        let initiated_hits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events \
             WHERE stream_id = $1 \
               AND event_type = 'ArtifactGroupInitiated' \
               AND event_data->'data'->'coords'->>'name' = $2",
        )
        .bind(format!("artifact_group-{group_id}"))
        .bind(SENTINEL_NAME)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            initiated_hits, 1,
            "coords.name sentinel must survive the append verbatim"
        );

        // Follow-up remove with a distinctive reason.
        let remove_batch = AppendEvents {
            stream_id: StreamId::artifact_group(group_id),
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(DomainEvent::ArtifactGroupMemberRemoved(
                ArtifactGroupMemberRemoved {
                    group_id,
                    artifact_id: artifact,
                    reason: Some(SENTINEL_REASON.into()),
                },
            ))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
        };
        adapter
            .commit_member_removed(group_id, artifact, remove_batch)
            .await
            .unwrap();

        let removed_hits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events \
             WHERE stream_id = $1 \
               AND event_type = 'ArtifactGroupMemberRemoved' \
               AND event_data->'data'->>'reason' = $2",
        )
        .bind(format!("artifact_group-{group_id}"))
        .bind(SENTINEL_REASON)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(removed_hits, 1, "reason sentinel survived");

        // Negative half — a rolled-back loser's payload must NOT
        // appear anywhere. Build a second first-placement batch with
        // a DIFFERENT sentinel, same (repo, coords). The adapter
        // short-circuits with `GroupAlreadyExists` and nothing lands.
        const LOSER_SENTINEL: &str = "LOSER_SENTINEL_MUST_NOT_PERSIST";
        let loser_coords = maven_coords(SENTINEL_NAME, "1.0.0"); // same logical coords
        let loser_group = make_group(repo, &loser_coords, "jar");
        // Fabricate a distinctive sentinel in the event payload — we
        // embed it into the correlation_id-level trace via a dummy
        // Initiated payload whose coords.name carries LOSER_SENTINEL.
        // But (repo, coords) must match the winner so ON CONFLICT
        // fires. We use a FRESH ArtifactCoords struct with the winner
        // coords but mark the event payload distinctively by using
        // a different `primary_role` value and looking for it.
        let loser_art = seed_artifact(&pool, repo, "loser.jar").await;
        let loser_change = GroupMemberCommit {
            new_group: Some(loser_group.clone()),
            member: ArtifactGroupMember {
                role: LOSER_SENTINEL.into(),
                artifact_id: loser_art,
                added_at: Utc::now(),
            },
            primary_role_assigned: None,
        };
        // The LOSER sentinel rides in the MemberAdded.role field.
        let loser_batch = AppendEvents {
            stream_id: StreamId::artifact_group(loser_group.id),
            expected_version: ExpectedVersion::NoStream,
            events: vec![
                EventToAppend::new(DomainEvent::ArtifactGroupInitiated(
                    ArtifactGroupInitiated {
                        group_id: loser_group.id,
                        repository_id: repo,
                        coords: loser_coords.clone(),
                        primary_role: "jar".into(),
                    },
                )),
                EventToAppend::new(DomainEvent::ArtifactGroupMemberAdded(
                    ArtifactGroupMemberAdded {
                        group_id: loser_group.id,
                        role: LOSER_SENTINEL.into(),
                        artifact_id: loser_art,
                    },
                )),
            ],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
        };
        let loser_outcome = adapter
            .commit_member_added(loser_change, loser_batch)
            .await
            .expect("loser returns typed outcome, not Err");
        assert!(matches!(
            loser_outcome,
            GroupCommitOutcome::GroupAlreadyExists { .. }
        ));

        // The LOSER's sentinel must NOT appear anywhere in
        // events.event_data — the transaction rolled back entirely,
        // so neither the Initiated nor the MemberAdded payload
        // persisted.
        let loser_leak: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events \
             WHERE event_data::text LIKE $1",
        )
        .bind(format!("%{LOSER_SENTINEL}%"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            loser_leak, 0,
            "rolled-back loser sentinel must not appear in events"
        );

        cleanup_repo(&pool, repo).await;
    }
}
