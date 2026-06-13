//! PostgreSQL write-side adapter for `mutable_refs` + its event stream.
//!
//! Implements [`RefLifecyclePort`]. Wraps the projection-row write and the
//! event append in a single transaction via [`PgEventStore::append_in_tx`]
//! so neither side can land without the other.
//!
//! **Adapter-authoritative idempotence.** `move_ref` locks the existing
//! projection row with `SELECT ... FOR UPDATE` inside the transaction and
//! re-reads the current target. If the target already matches the
//! caller-supplied target, the adapter commits WITHOUT appending a
//! `RefMoved`. This is what defeats the concurrent same-target race; the
//! use-case layer's read-then-check is a performance optimisation only.
//!
//! **Concurrent first-placement** surfaces as
//! [`RefCommitOutcome::RefAlreadyExists`]. The adapter uses
//! `INSERT ... ON CONFLICT (repository_id, namespace, ref_name) DO NOTHING
//! RETURNING id` on the first-placement path; empty RETURNING rolls the
//! whole transaction back (discarding `batch` verbatim — mirrors Item 6's
//! adapter-never-mutates-payloads rule for groups) and surfaces the
//! winner's id so the use case can retry as a move. Pre-review-B5 this
//! path used `ON CONFLICT DO UPDATE` and two concurrent first-placement
//! calls left one RefMoved event orphaned on the loser's tentative
//! `ref-<id>` stream — fixed in commit 2 of the review-B5/B6/M5 series.
//!
//! See design doc §2.4 and §2.9.

use std::sync::Arc;

use sqlx::Row;
use uuid::Uuid;

use hort_domain::entities::mutable_ref::{MutableRef, RefTarget};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::event_store::AppendEvents;
use hort_domain::ports::ref_lifecycle::{RefCommitOutcome, RefLifecyclePort};
use hort_domain::ports::BoxFuture;

use crate::event_store::PgEventStore;

/// PostgreSQL implementation of [`RefLifecyclePort`].
pub struct PgRefLifecycle {
    event_store: Arc<PgEventStore>,
}

impl PgRefLifecycle {
    /// Construct the adapter. The transactional path goes through
    /// `event_store.begin_unit_of_work()`; no separate pool handle is
    /// needed.
    pub fn new(event_store: Arc<PgEventStore>) -> Self {
        Self { event_store }
    }
}

/// The three target columns on the `mutable_refs` row, read as a tuple
/// so the adapter can compare against the caller-supplied `RefTarget`
/// without materialising a full `MutableRef`.
#[derive(Debug, PartialEq, Eq)]
struct CurrentTarget {
    kind: String,
    hash: Option<String>,
    version: Option<String>,
}

impl CurrentTarget {
    /// Translate the incoming [`RefTarget`] into the same tuple shape so
    /// the in-transaction idempotence comparison is a plain tuple equality.
    fn from_target(t: &RefTarget) -> Self {
        match t {
            RefTarget::ContentHash(h) => Self {
                kind: "hash".into(),
                hash: Some(h.as_ref().to_string()),
                version: None,
            },
            RefTarget::Version(v) => Self {
                kind: "version".into(),
                hash: None,
                version: Some(v.clone()),
            },
        }
    }
}

impl RefLifecyclePort for PgRefLifecycle {
    fn move_ref(
        &self,
        r: MutableRef,
        batch: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<RefCommitOutcome>> {
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;

            // Lock the existing row (if any) and read its current target.
            // When the row is absent the lock is a no-op and we fall into
            // the first-placement branch below.
            let row = sqlx::query(
                r#"SELECT target_kind, target_hash, target_version
                   FROM mutable_refs
                   WHERE repository_id = $1 AND namespace = $2 AND ref_name = $3
                   FOR UPDATE"#,
            )
            .bind(r.repository_id)
            .bind(&r.namespace)
            .bind(&r.ref_name)
            .fetch_optional(uow.conn())
            .await
            .map_err(|e| {
                DomainError::Invariant(format!("mutable_refs FOR UPDATE read failed: {e}"))
            })?;

            let desired = CurrentTarget::from_target(&r.target);

            if let Some(row) = row {
                // Existing-row path: UPDATE in place, keep the row's id
                // stable so the event stream continues to share the
                // projection row's primary key.
                let current = CurrentTarget {
                    kind: row.get::<String, _>("target_kind"),
                    hash: row.get::<Option<String>, _>("target_hash"),
                    version: row.get::<Option<String>, _>("target_version"),
                };
                if current == desired {
                    // Adapter-authoritative idempotence short-circuit.
                    // Commit the (no-op) transaction to release the
                    // FOR UPDATE lock; no event appended. This keeps the
                    // concurrent-same-target race from double-emitting.
                    uow.commit().await?;
                    return Ok(RefCommitOutcome::Committed);
                }

                sqlx::query(
                    r#"UPDATE mutable_refs
                       SET target_kind    = $1,
                           target_hash    = $2,
                           target_version = $3,
                           updated_at     = NOW()
                       WHERE repository_id = $4 AND namespace = $5 AND ref_name = $6"#,
                )
                .bind(&desired.kind)
                .bind(&desired.hash)
                .bind(&desired.version)
                .bind(r.repository_id)
                .bind(&r.namespace)
                .bind(&r.ref_name)
                .execute(uow.conn())
                .await
                .map_err(|e| DomainError::Invariant(format!("mutable_refs UPDATE failed: {e}")))?;

                self.event_store.append_in_tx(&mut uow, batch).await?;
                uow.commit().await?;
                return Ok(RefCommitOutcome::Committed);
            }

            // First-placement path. `INSERT ... ON CONFLICT DO NOTHING
            // RETURNING id` collapses the "did we win the create race?"
            // question into a single round-trip. Empty RETURNING means
            // another writer landed first — roll back the whole
            // transaction (discarding `batch` verbatim, same guarantee
            // as Item 6 for groups) and return the winner's id.
            let inserted: Option<Uuid> = sqlx::query_scalar(
                r#"INSERT INTO mutable_refs (
                       id, repository_id, namespace, ref_name,
                       target_kind, target_hash, target_version,
                       created_at, updated_at
                   ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
                   ON CONFLICT (repository_id, namespace, ref_name) DO NOTHING
                   RETURNING id"#,
            )
            .bind(r.id)
            .bind(r.repository_id)
            .bind(&r.namespace)
            .bind(&r.ref_name)
            .bind(&desired.kind)
            .bind(&desired.hash)
            .bind(&desired.version)
            .fetch_optional(uow.conn())
            .await
            .map_err(|e| DomainError::Invariant(format!("mutable_refs INSERT failed: {e}")))?;

            match inserted {
                Some(_) => {
                    // Our INSERT won the race — append in the same txn
                    // and commit.
                    self.event_store.append_in_tx(&mut uow, batch).await?;
                    uow.commit().await?;
                    Ok(RefCommitOutcome::Committed)
                }
                None => {
                    // A concurrent writer got there first. Look up the
                    // winner's id, then drop `uow` to roll back — the
                    // loser's `batch` is discarded verbatim; no event
                    // stream is created for the loser's tentative id.
                    let existing_id: Uuid = sqlx::query_scalar(
                        r#"SELECT id FROM mutable_refs
                           WHERE repository_id = $1 AND namespace = $2 AND ref_name = $3"#,
                    )
                    .bind(r.repository_id)
                    .bind(&r.namespace)
                    .bind(&r.ref_name)
                    .fetch_one(uow.conn())
                    .await
                    .map_err(|e| {
                        DomainError::Invariant(format!(
                            "mutable_refs lookup after ON CONFLICT race failed: {e}"
                        ))
                    })?;
                    tracing::warn!(
                        %existing_id,
                        tentative_id = %r.id,
                        "concurrent ref creation observed; rolling back and returning RefAlreadyExists"
                    );
                    drop(uow);
                    Ok(RefCommitOutcome::RefAlreadyExists { existing_id })
                }
            }
        })
    }

    fn retire_ref(
        &self,
        repo: Uuid,
        namespace: &str,
        ref_name: &str,
        batch: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<()>> {
        let namespace = namespace.to_string();
        let ref_name = ref_name.to_string();
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;

            // `RETURNING id` lets us decide whether the row existed in a
            // single round-trip. Zero rows → NotFound, without touching
            // the event log. The transaction is dropped (rolled back) on
            // return.
            let deleted = sqlx::query(
                r#"DELETE FROM mutable_refs
                   WHERE repository_id = $1 AND namespace = $2 AND ref_name = $3
                   RETURNING id"#,
            )
            .bind(repo)
            .bind(&namespace)
            .bind(&ref_name)
            .fetch_optional(uow.conn())
            .await
            .map_err(|e| DomainError::Invariant(format!("mutable_refs DELETE failed: {e}")))?;

            if deleted.is_none() {
                // Explicit rollback so the transaction's resources are
                // released immediately (dropping `uow` would also roll
                // back, but the explicit call keeps the intent obvious).
                return Err(DomainError::NotFound {
                    entity: "MutableRef",
                    id: format!("{repo}/{namespace}/{ref_name}"),
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

    use hort_domain::types::ContentHash;

    /// Compile-time proof the adapter implements the port. Runtime
    /// invocation is covered by the integration tests below.
    #[test]
    fn pg_ref_lifecycle_implements_port() {
        fn _assert_port<T: RefLifecyclePort>() {}
        _assert_port::<PgRefLifecycle>();
    }

    #[test]
    fn current_target_from_hash_target() {
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        let ct = CurrentTarget::from_target(&RefTarget::ContentHash(hash));
        assert_eq!(ct.kind, "hash");
        assert!(ct.hash.is_some());
        assert!(ct.version.is_none());
    }

    #[test]
    fn current_target_from_version_target() {
        let ct = CurrentTarget::from_target(&RefTarget::Version("1.2.3".into()));
        assert_eq!(ct.kind, "version");
        assert!(ct.hash.is_none());
        assert_eq!(ct.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn current_target_equality_tuple_match() {
        let a = CurrentTarget {
            kind: "hash".into(),
            hash: Some("x".repeat(64)),
            version: None,
        };
        let b = CurrentTarget {
            kind: "hash".into(),
            hash: Some("x".repeat(64)),
            version: None,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn current_target_equality_different_kind() {
        let a = CurrentTarget {
            kind: "hash".into(),
            hash: Some("x".repeat(64)),
            version: None,
        };
        let b = CurrentTarget {
            kind: "version".into(),
            hash: None,
            version: Some("1.0.0".into()),
        };
        assert_ne!(a, b);
    }

    // ---------------------------------------------------------------
    // DB-backed integration tests — mirror `ref_registry_repo.rs`
    // conventions: skipped (noisy pass) when `DATABASE_URL` is unset.
    // ---------------------------------------------------------------

    use chrono::Utc;
    use hort_domain::entities::mutable_ref::MutableRef;
    use hort_domain::events::{Actor, ApiActor, DomainEvent, RefMoved, StreamId};
    use hort_domain::ports::event_store::{EventToAppend, ExpectedVersion};
    use hort_domain::ports::ref_lifecycle::RefCommitOutcome;
    use sqlx::PgPool;
    use std::env;

    const VALID_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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
        let key = format!("it-refwrite-{}", id.simple());
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

    fn build_move_batch(r: &MutableRef, from: Option<RefTarget>) -> AppendEvents {
        AppendEvents {
            stream_id: StreamId::ref_(r.id),
            expected_version: if from.is_some() {
                ExpectedVersion::Any
            } else {
                ExpectedVersion::NoStream
            },
            events: vec![EventToAppend::new(DomainEvent::RefMoved(RefMoved {
                ref_id: r.id,
                repository_id: r.repository_id,
                namespace: r.namespace.clone(),
                ref_name: r.ref_name.clone(),
                from,
                to: r.target.clone(),
            }))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
        }
    }

    /// Concurrent same-target `move_ref` calls race against the FOR
    /// UPDATE row lock; exactly ONE of them appends the `RefMoved` row
    /// (the one that creates the projection). The second caller sees
    /// the fresh target on re-read and commits without appending.
    ///
    /// Variation: we seed the projection row first (version 1.0.0) and
    /// then race two moves to 2.0.0. Both must succeed at the
    /// `move_ref` call level; exactly ONE `RefMoved` event lands.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn concurrent_same_target_move_emits_exactly_one_event() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        // Seed the initial ref so the two racers both have something
        // to lock on.
        let existing_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO mutable_refs (
                   id, repository_id, namespace, ref_name,
                   target_kind, target_hash, target_version
               ) VALUES ($1, $2, $3, $4, 'version', NULL, $5)"#,
        )
        .bind(existing_id)
        .bind(repo)
        .bind("express")
        .bind("latest")
        .bind("1.0.0")
        .execute(&pool)
        .await
        .expect("seed mutable_ref");

        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        let adapter = Arc::new(PgRefLifecycle::new(event_store.clone()));

        // Record the updated_at prior to the race — we assert it bumps
        // exactly once.
        let pre_updated_at: chrono::DateTime<Utc> =
            sqlx::query_scalar("SELECT updated_at FROM mutable_refs WHERE id = $1")
                .bind(existing_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        let new_target = RefTarget::Version("2.0.0".into());
        let make_mref = || MutableRef {
            id: existing_id,
            repository_id: repo,
            namespace: "express".into(),
            ref_name: "latest".into(),
            target: new_target.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let a = adapter.clone();
        let b = adapter.clone();
        let r_a = make_mref();
        let r_b = make_mref();
        let prior = Some(RefTarget::Version("1.0.0".into()));
        let batch_a = build_move_batch(&r_a, prior.clone());
        let batch_b = build_move_batch(&r_b, prior);

        let (res_a, res_b) = tokio::join!(
            tokio::spawn(async move { a.move_ref(r_a, batch_a).await }),
            tokio::spawn(async move { b.move_ref(r_b, batch_b).await })
        );
        res_a.unwrap().expect("first move_ref succeeds");
        res_b
            .unwrap()
            .expect("second move_ref succeeds (no-op short-circuit)");

        // Exactly one RefMoved row in `events` for this stream.
        let event_count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM events
               WHERE stream_id = $1 AND event_type = 'RefMoved'"#,
        )
        .bind(format!("ref-{existing_id}"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(event_count, 1, "exactly one RefMoved event lands");

        // The projection row's updated_at bumped exactly once compared
        // to the seed value.
        let post_updated_at: chrono::DateTime<Utc> =
            sqlx::query_scalar("SELECT updated_at FROM mutable_refs WHERE id = $1")
                .bind(existing_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            post_updated_at > pre_updated_at,
            "updated_at must have bumped at least once"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// Transactional abort: feed `move_ref` a batch whose event fails
    /// `validate_and_serialize` (oversize string). The adapter's
    /// `append_in_tx` must surface the error; the transaction rolls
    /// back; neither the projection row nor the event row lands.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn transactional_abort_leaves_both_sides_uncommitted() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        let adapter = PgRefLifecycle::new(event_store.clone());

        let ref_id = Uuid::new_v4();
        let r = MutableRef {
            id: ref_id,
            repository_id: repo,
            namespace: "library/nginx".into(),
            ref_name: "latest".into(),
            target: RefTarget::ContentHash(VALID_HASH.parse().unwrap()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Build a batch with a `RefMoved` whose `namespace` exceeds the
        // 512-char domain cap — `event.validate()` returns
        // `DomainError::Validation`, which `append_in_tx` propagates.
        let bad_batch = AppendEvents {
            stream_id: StreamId::ref_(ref_id),
            expected_version: ExpectedVersion::NoStream,
            events: vec![EventToAppend::new(DomainEvent::RefMoved(RefMoved {
                ref_id,
                repository_id: repo,
                namespace: "x".repeat(600), // > MAX_NAMESPACE_LEN (512)
                ref_name: "latest".into(),
                from: None,
                to: RefTarget::ContentHash(VALID_HASH.parse().unwrap()),
            }))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
        };

        let err = adapter
            .move_ref(r, bad_batch)
            .await
            .expect_err("validation must fail");
        assert!(
            matches!(err, DomainError::Validation(_)),
            "expected Validation, got: {err}"
        );

        // Projection row did NOT land.
        let row_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mutable_refs \
             WHERE repository_id = $1 AND namespace = $2 AND ref_name = $3",
        )
        .bind(repo)
        .bind("library/nginx")
        .bind("latest")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row_count, 0, "projection row must not commit on abort");

        // Event row did NOT land.
        let event_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE stream_id = $1")
                .bind(format!("ref-{ref_id}"))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(event_count, 0, "event row must not commit on abort");

        cleanup_repo(&pool, repo).await;
    }

    /// First-placement path: `move_ref` creates the projection row AND
    /// appends the `RefMoved { from: None }` event under a single txn.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn first_placement_creates_row_and_event() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        let adapter = PgRefLifecycle::new(event_store.clone());

        let ref_id = Uuid::new_v4();
        let target = RefTarget::ContentHash(VALID_HASH.parse().unwrap());
        let r = MutableRef {
            id: ref_id,
            repository_id: repo,
            namespace: "library/nginx".into(),
            ref_name: "latest".into(),
            target: target.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let batch = build_move_batch(&r, None);

        let outcome = adapter.move_ref(r, batch).await.unwrap();
        assert!(matches!(outcome, RefCommitOutcome::Committed));

        let stored_kind: String =
            sqlx::query_scalar("SELECT target_kind FROM mutable_refs WHERE id = $1")
                .bind(ref_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored_kind, "hash");

        let event_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE stream_id = $1")
                .bind(format!("ref-{ref_id}"))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(event_count, 1);

        cleanup_repo(&pool, repo).await;
    }

    /// B5 regression guard: two concurrent first-placements of the same
    /// `(repo, namespace, ref_name)` with DIFFERENT tentative `ref_id`s
    /// must produce exactly ONE `RefMoved` event on the winner's stream
    /// and ZERO events on the loser's tentative stream. The loser's
    /// `batch` is discarded verbatim when `INSERT ON CONFLICT DO NOTHING`
    /// returns empty; the adapter surfaces
    /// `Ok(RefCommitOutcome::RefAlreadyExists { existing_id = winner_id })`.
    ///
    /// Pre-fix the adapter used `ON CONFLICT DO UPDATE`: both racers
    /// appended to their own tentative stream, leaving an orphan
    /// `RefMoved` on the loser's `ref-<loser_id>` stream. This test is
    /// the regression guard.
    /// Wait for at least one session on `pool` to be blocked on a
    /// transactionid lock — i.e. an `INSERT` waiting for an
    /// uncommitted conflicting row to resolve. The observation loop
    /// exits as soon as the adapter is confirmed blocked; the 10 ms
    /// probe interval is a polling cadence, not a race timer.
    /// Bounded retry guards against environments where the lock wait
    /// never materialises (caller signals a test bug, not a flake).
    /// Wait until a backend is blocked **specifically by the
    /// transaction whose backend pid is `blocker_pid`** (the raw winner
    /// txn). Scoping via `pg_blocking_pids` makes the probe immune to
    /// unrelated `transactionid` Lock waiters created by sibling
    /// DB-backed tests — `cargo test --lib` runs them in parallel
    /// against one Postgres, and the previous server-global
    /// `pg_stat_activity` count false-positived on those, flaking this
    /// test in CI (`test:integration`).
    async fn wait_for_blocked_insert(pool: &PgPool, blocker_pid: i32) {
        for _ in 0..500 {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE wait_event_type = 'Lock' \
                   AND state = 'active' \
                   AND $1 = ANY(pg_blocking_pids(pid))",
            )
            .bind(blocker_pid)
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting > 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("adapter never blocked on the unique-index lock (5s budget exhausted)");
    }

    /// B5 regression guard — deterministic via pg_stat_activity polling.
    ///
    /// The flaky tokio-barrier variant of this test was replaced once
    /// it turned out that userspace scheduling does not reliably force
    /// both tasks into the adapter's INSERT at the same moment. Instead
    /// we hold an uncommitted raw transaction whose INSERT has taken
    /// the unique-index lock, spawn the adapter on a DIFFERENT
    /// tentative id, and wait (observationally) for it to block on
    /// that lock before committing the raw transaction. Postgres
    /// semantics guarantee that unique-index conflict waiters wait
    /// until the first writer commits or aborts; committing forces the
    /// adapter's `INSERT ... ON CONFLICT DO NOTHING` to return empty
    /// `RETURNING`, which is the exact code path B5 fixed.
    ///
    /// Asserts:
    /// - The adapter returns `Ok(RefAlreadyExists { existing_id })`
    ///   with the winner's id.
    /// - The projection row keeps the winner's id (not the loser's
    ///   tentative id).
    /// - The loser's tentative `ref-<id_b>` stream is orphan-free.
    ///   Pre-fix the UPSERT path appended a `RefMoved` there.
    ///
    /// We do NOT spawn two adapter calls here; the winner side is set
    /// up via raw SQL so we can deterministically control its commit
    /// point. The symmetric winner-path is covered by
    /// `first_placement_creates_row_and_event` (single-writer) and
    /// `concurrent_same_target_move_emits_exactly_one_event` (update
    /// race, pre-seeded row).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial(hort_pg_db)]
    async fn concurrent_first_placement_no_orphan_event_stream() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        let adapter = Arc::new(PgRefLifecycle::new(event_store.clone()));

        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        assert_ne!(id_a, id_b);
        let ns = "library/nginx";
        let name = "latest";
        // Winner (raw-SQL-inserted) carries a Version target.
        // Loser (adapter-driven) carries a different target so the
        // "same target" short-circuit cannot mask the race.
        let winner_version = "1.0.0";
        let loser_target = RefTarget::ContentHash(VALID_HASH.parse().unwrap());

        // Step 1 — open a raw transaction on the pool, INSERT the
        // winner's row with id_a, DO NOT commit yet. The unique-index
        // lock is now held by this uncommitted transaction.
        let mut raw_tx = pool.begin().await.expect("open raw transaction");
        // Backend pid of the winner txn. The block-wait probe filters on
        // `pg_blocking_pids` against this pid, so concurrent unrelated
        // transactionid waiters from sibling parallel tests can't
        // false-positive it.
        let winner_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *raw_tx)
            .await
            .expect("winner backend pid");
        sqlx::query(
            r#"INSERT INTO mutable_refs
                   (id, repository_id, namespace, ref_name,
                    target_kind, target_hash, target_version,
                    created_at, updated_at)
               VALUES ($1, $2, $3, $4, 'version', NULL, $5, NOW(), NOW())"#,
        )
        .bind(id_a)
        .bind(repo)
        .bind(ns)
        .bind(name)
        .bind(winner_version)
        .execute(&mut *raw_tx)
        .await
        .expect("raw INSERT of winner row");

        // Step 2 — spawn the adapter on the loser's tentative id.
        // Its `INSERT ... ON CONFLICT DO NOTHING RETURNING id` will
        // block on the unique-index lock held by the raw txn.
        let r_loser = MutableRef {
            id: id_b,
            repository_id: repo,
            namespace: ns.into(),
            ref_name: name.into(),
            target: loser_target,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let batch_loser = build_move_batch(&r_loser, None);
        let adapter_spawned = adapter.clone();
        let join_loser =
            tokio::spawn(async move { adapter_spawned.move_ref(r_loser, batch_loser).await });

        // Step 3 — observationally wait for the adapter to block on
        // the unique-index lock, scoped to the winner txn's backend
        // pid. 10 ms probe cadence, not a race timer; exit condition is
        // "a backend is blocked specifically by `winner_pid`".
        wait_for_blocked_insert(&pool, winner_pid).await;

        // Step 4 — commit the raw txn. The adapter's INSERT unblocks,
        // observes the conflict, ON CONFLICT DO NOTHING returns empty
        // RETURNING, the SELECT id path runs, the whole adapter txn
        // rolls back, `Ok(RefAlreadyExists { existing_id: id_a })`
        // surfaces.
        raw_tx.commit().await.expect("commit raw winner txn");

        let outcome = join_loser
            .await
            .expect("spawned task joined")
            .expect("move_ref returned an outcome");

        match outcome {
            RefCommitOutcome::RefAlreadyExists { existing_id } => {
                assert_eq!(
                    existing_id, id_a,
                    "loser observes winner's id from the projection"
                );
            }
            RefCommitOutcome::Committed => {
                panic!("loser should have surfaced RefAlreadyExists, got Committed")
            }
        }

        // Projection: exactly one row with id = id_a. The loser's
        // tentative id is absent.
        let projection_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM mutable_refs \
             WHERE repository_id = $1 AND namespace = $2 AND ref_name = $3",
        )
        .bind(repo)
        .bind(ns)
        .bind(name)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(projection_ids, vec![id_a], "exactly one row, winner's id");

        // ZERO events on the loser's tentative stream — the whole
        // adapter txn rolled back, so `append_in_tx` never landed.
        // This is the load-bearing assertion: pre-fix the UPSERT path
        // appended an orphan `RefMoved` on `ref-<id_b>`.
        let loser_event_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE stream_id = $1")
                .bind(format!("ref-{id_b}"))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            loser_event_count, 0,
            "loser's tentative stream must be empty (orphan-free)"
        );

        // ZERO RefMoved events on the winner's stream too — this test
        // set up the winner via raw SQL, not through the adapter, so
        // no event was emitted for the winner side. The winner-path
        // event emission is covered by `first_placement_creates_row_and_event`.
        let winner_event_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE stream_id = $1")
                .bind(format!("ref-{id_a}"))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            winner_event_count, 0,
            "winner was seeded via raw SQL, so no adapter-emitted event"
        );

        cleanup_repo(&pool, repo).await;
    }

    /// `retire_ref` on a nonexistent ref returns NotFound and does NOT
    /// append the RefRetired event.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn retire_ref_missing_returns_not_found_without_event() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        let adapter = PgRefLifecycle::new(event_store.clone());

        let ghost_id = Uuid::new_v4();
        let batch = AppendEvents {
            stream_id: StreamId::ref_(ghost_id),
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(DomainEvent::RefRetired(
                hort_domain::events::RefRetired {
                    ref_id: ghost_id,
                    repository_id: repo,
                    namespace: "ghost".into(),
                    ref_name: "latest".into(),
                    last_target: RefTarget::Version("1.0.0".into()),
                },
            ))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
        };

        let err = adapter
            .retire_ref(repo, "ghost", "latest", batch)
            .await
            .expect_err("missing ref must surface NotFound");
        assert!(
            matches!(
                err,
                DomainError::NotFound {
                    entity: "MutableRef",
                    ..
                }
            ),
            "got: {err}"
        );

        // No stream-<ghost_id> event row.
        let event_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE stream_id = $1")
                .bind(format!("ref-{ghost_id}"))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(event_count, 0);

        cleanup_repo(&pool, repo).await;
    }
}
