//! PostgreSQL read-side adapter for the `mutable_refs` projection.
//!
//! Implements [`RefRegistryPort`]. Writes live on the (not-yet-shipped)
//! `RefLifecyclePort`. This adapter does reads only: `find`, `list`,
//! `find_by_target`.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use hort_domain::entities::mutable_ref::{MutableRef, RefTarget};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::ref_registry::RefRegistryPort;

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`RefRegistryPort`].
///
/// Thin wrapper over a `PgPool`; no per-instance state beyond the pool.
/// Construction is cheap (no I/O) — the pool itself governs connection
/// lifecycle.
pub struct PgRefRegistry {
    pool: PgPool,
}

impl PgRefRegistry {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// SQL fragment selecting every column needed to build a [`MutableRef`].
///
/// `target_kind` + the two target columns are read side-by-side and
/// resolved in Rust (via [`row_to_ref`]); attempting the same logic
/// inline in SQL (`CASE WHEN target_kind ...`) would obscure the
/// domain's closed-enum contract.
const SELECT_COLS: &str = r#"
    id, repository_id, namespace, ref_name,
    target_kind, target_hash, target_version,
    created_at, updated_at
"#;

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

/// Wire shape for a `mutable_refs` row. Translation to the domain
/// [`MutableRef`] happens in [`row_to_ref`], which enforces the
/// target-kind / target-column invariant the migration's CHECK
/// constraint establishes.
#[derive(Debug, FromRow)]
struct MutableRefRow {
    id: Uuid,
    repository_id: Uuid,
    namespace: String,
    ref_name: String,
    target_kind: String,
    target_hash: Option<String>,
    target_version: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Translate a row into a domain [`MutableRef`].
///
/// The database CHECK constraint guarantees that exactly one of
/// `target_hash` / `target_version` is populated for each `target_kind`.
/// If a row arrives with a corrupt combination (CHECK bypassed,
/// migration drift, manual edit), we surface `DomainError::Invariant`
/// rather than silently picking a default — a corrupted projection is
/// not a lookup miss.
fn row_to_ref(row: MutableRefRow) -> DomainResult<MutableRef> {
    let target = match row.target_kind.as_str() {
        "hash" => {
            let hash_str = row.target_hash.ok_or_else(|| {
                DomainError::Invariant(format!(
                    "mutable_refs row {}: target_kind='hash' but target_hash IS NULL",
                    row.id
                ))
            })?;
            let hash = hash_str.parse().map_err(|e| {
                DomainError::Invariant(format!(
                    "mutable_refs row {}: target_hash is not a valid SHA-256: {e}",
                    row.id
                ))
            })?;
            RefTarget::ContentHash(hash)
        }
        "version" => {
            let version = row.target_version.ok_or_else(|| {
                DomainError::Invariant(format!(
                    "mutable_refs row {}: target_kind='version' but target_version IS NULL",
                    row.id
                ))
            })?;
            RefTarget::Version(version)
        }
        other => {
            return Err(DomainError::Invariant(format!(
                "mutable_refs row {}: unknown target_kind {other:?}",
                row.id
            )));
        }
    };
    Ok(MutableRef {
        id: row.id,
        repository_id: row.repository_id,
        namespace: row.namespace,
        ref_name: row.ref_name,
        target,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

// ---------------------------------------------------------------------------
// Port impl
// ---------------------------------------------------------------------------

impl RefRegistryPort for PgRefRegistry {
    fn find(
        &self,
        repo: Uuid,
        namespace: &str,
        ref_name: &str,
    ) -> BoxFuture<'_, DomainResult<MutableRef>> {
        let namespace = namespace.to_owned();
        let ref_name = ref_name.to_owned();
        Box::pin(async move {
            tracing::debug!(
                entity = "MutableRef",
                %repo,
                namespace = %namespace,
                ref_name = %ref_name,
                "find"
            );
            let sql = format!(
                "SELECT {SELECT_COLS} FROM mutable_refs \
                 WHERE repository_id = $1 AND namespace = $2 AND ref_name = $3"
            );
            let row: MutableRefRow = sqlx::query_as(&sql)
                .bind(repo)
                .bind(&namespace)
                .bind(&ref_name)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "MutableRef", &format!("{repo}/{namespace}/{ref_name}"))
                })?;
            row_to_ref(row)
        })
    }

    fn list(&self, repo: Uuid, namespace: &str) -> BoxFuture<'_, DomainResult<Vec<MutableRef>>> {
        let namespace = namespace.to_owned();
        Box::pin(async move {
            tracing::debug!(
                entity = "MutableRef",
                %repo,
                namespace = %namespace,
                "list"
            );
            let sql = format!(
                "SELECT {SELECT_COLS} FROM mutable_refs \
                 WHERE repository_id = $1 AND namespace = $2 \
                 ORDER BY ref_name"
            );
            let rows: Vec<MutableRefRow> = sqlx::query_as(&sql)
                .bind(repo)
                .bind(&namespace)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "MutableRef", &format!("list/{repo}/{namespace}"))
                })?;
            rows.into_iter().map(row_to_ref).collect()
        })
    }

    fn find_by_target(
        &self,
        repo: Uuid,
        target: &RefTarget,
    ) -> BoxFuture<'_, DomainResult<Vec<MutableRef>>> {
        // Clone the queried scalar so the returned future is `'static`.
        // Discriminating here (vs inline inside `async move`) keeps the
        // SQL bound parameter typed statically — `target_hash` binds a
        // `&str` (CHAR(64) column), `target_version` binds a `&str`
        // (TEXT column). The two code paths are narrow enough that
        // splitting them reads more clearly than a polymorphic bind.
        let target = target.clone();
        Box::pin(async move {
            match target {
                RefTarget::ContentHash(ref hash) => {
                    tracing::debug!(
                        entity = "MutableRef",
                        %repo,
                        kind = "hash",
                        "find_by_target"
                    );
                    let sql = format!(
                        "SELECT {SELECT_COLS} FROM mutable_refs \
                         WHERE repository_id = $1 \
                           AND target_kind = 'hash' \
                           AND target_hash = $2 \
                         ORDER BY namespace, ref_name"
                    );
                    let rows: Vec<MutableRefRow> = sqlx::query_as(&sql)
                        .bind(repo)
                        .bind(hash.as_ref())
                        .fetch_all(&self.pool)
                        .await
                        .map_err(|e| {
                            map_sqlx_error(&e, "MutableRef", &format!("target_hash/{repo}"))
                        })?;
                    rows.into_iter().map(row_to_ref).collect()
                }
                RefTarget::Version(ref version) => {
                    tracing::debug!(
                        entity = "MutableRef",
                        %repo,
                        kind = "version",
                        "find_by_target"
                    );
                    let sql = format!(
                        "SELECT {SELECT_COLS} FROM mutable_refs \
                         WHERE repository_id = $1 \
                           AND target_kind = 'version' \
                           AND target_version = $2 \
                         ORDER BY namespace, ref_name"
                    );
                    let rows: Vec<MutableRefRow> = sqlx::query_as(&sql)
                        .bind(repo)
                        .bind(version)
                        .fetch_all(&self.pool)
                        .await
                        .map_err(|e| {
                            map_sqlx_error(&e, "MutableRef", &format!("target_version/{repo}"))
                        })?;
                    rows.into_iter().map(row_to_ref).collect()
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests (compile-time + row mapping — DB-backed integration tests live in
// `tests/ref_registry_repo_integration.rs`, gated on DATABASE_URL)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Compile-time proof the adapter implements the port. Runtime
    /// invocation is covered by the integration test module.
    #[tokio::test]
    async fn pg_ref_registry_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgRefRegistry::new(pool);
    }

    #[test]
    fn pg_ref_registry_implements_port() {
        fn _assert_port<T: RefRegistryPort>() {}
        _assert_port::<PgRefRegistry>();
    }

    // -- row_to_ref -----------------------------------------------------

    const VALID_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn sample_row_hash() -> MutableRefRow {
        MutableRefRow {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            namespace: "library/nginx".into(),
            ref_name: "latest".into(),
            target_kind: "hash".into(),
            target_hash: Some(VALID_HASH.into()),
            target_version: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn sample_row_version() -> MutableRefRow {
        MutableRefRow {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            namespace: "express".into(),
            ref_name: "latest".into(),
            target_kind: "version".into(),
            target_hash: None,
            target_version: Some("4.18.2".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn row_to_ref_hash_ok() {
        let mref = row_to_ref(sample_row_hash()).unwrap();
        match mref.target {
            RefTarget::ContentHash(h) => assert_eq!(h.as_ref(), VALID_HASH),
            RefTarget::Version(_) => panic!("expected ContentHash"),
        }
    }

    #[test]
    fn row_to_ref_version_ok() {
        let mref = row_to_ref(sample_row_version()).unwrap();
        match mref.target {
            RefTarget::Version(v) => assert_eq!(v, "4.18.2"),
            RefTarget::ContentHash(_) => panic!("expected Version"),
        }
    }

    #[test]
    fn row_to_ref_hash_kind_with_null_hash_is_invariant() {
        let row = MutableRefRow {
            target_hash: None,
            ..sample_row_hash()
        };
        let err = row_to_ref(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)), "got: {err}");
    }

    #[test]
    fn row_to_ref_version_kind_with_null_version_is_invariant() {
        let row = MutableRefRow {
            target_version: None,
            ..sample_row_version()
        };
        let err = row_to_ref(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)), "got: {err}");
    }

    #[test]
    fn row_to_ref_unknown_kind_is_invariant() {
        let row = MutableRefRow {
            target_kind: "banana".into(),
            ..sample_row_hash()
        };
        let err = row_to_ref(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)), "got: {err}");
    }

    #[test]
    fn row_to_ref_hash_kind_with_invalid_hex_is_invariant() {
        let row = MutableRefRow {
            target_hash: Some("not-a-hash".into()),
            ..sample_row_hash()
        };
        let err = row_to_ref(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)), "got: {err}");
    }

    // ---------------------------------------------------------------
    // DB-backed integration tests. Skipped (noisy "pass") when
    // `DATABASE_URL` is unset — this mirrors the adapter-test
    // conventions in neighbouring crates and keeps `cargo test --lib`
    // green for developers without a local Postgres.
    //
    // When DATABASE_URL is set the harness:
    //   1. connects with a fresh pool,
    //   2. runs all pending migrations (idempotent),
    //   3. seeds a throwaway repository row + the rows we need,
    //   4. runs one assertion,
    //   5. cleans up with `ON DELETE CASCADE` on the repo row.
    //
    // Each test uses a random `repository_id`, so concurrent test
    // invocations don't collide.
    // ---------------------------------------------------------------

    use std::env;

    /// Non-None iff the runtime has a usable `DATABASE_URL`.
    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        // Apply migrations so the `mutable_refs` table exists even on
        // a fresh test database.
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    /// Create a disposable repository row and return its id. Rows we
    /// attach to it cascade away when we delete it in `cleanup_repo`.
    async fn seed_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("it-refs-{}", id.simple());
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

    /// Insert a `mutable_refs` row directly (no write port yet).
    async fn insert_ref(
        pool: &PgPool,
        repo: Uuid,
        namespace: &str,
        ref_name: &str,
        target: &RefTarget,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let (kind, hash, version) = match target {
            RefTarget::ContentHash(h) => ("hash", Some(h.as_ref().to_string()), None),
            RefTarget::Version(v) => ("version", None, Some(v.clone())),
        };
        sqlx::query(
            r#"INSERT INTO mutable_refs (
                   id, repository_id, namespace, ref_name,
                   target_kind, target_hash, target_version
               ) VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(id)
        .bind(repo)
        .bind(namespace)
        .bind(ref_name)
        .bind(kind)
        .bind(hash)
        .bind(version)
        .execute(pool)
        .await
        .expect("seed mutable_ref insert");
        id
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_roundtrip_for_seeded_ref() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let hash: hort_domain::types::ContentHash =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap();
        let _ = insert_ref(
            &pool,
            repo,
            "library/nginx",
            "latest",
            &RefTarget::ContentHash(hash.clone()),
        )
        .await;

        let adapter = PgRefRegistry::new(pool.clone());
        let got = adapter
            .find(repo, "library/nginx", "latest")
            .await
            .expect("find should return the seeded ref");
        assert_eq!(got.repository_id, repo);
        assert_eq!(got.namespace, "library/nginx");
        assert_eq!(got.ref_name, "latest");
        assert_eq!(got.target, RefTarget::ContentHash(hash));

        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_missing_returns_not_found() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = PgRefRegistry::new(pool.clone());
        let err = adapter
            .find(repo, "ghost/namespace", "latest")
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

        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_filters_by_repo_and_namespace() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo_a = seed_repo(&pool).await;
        let repo_b = seed_repo(&pool).await;

        insert_ref(
            &pool,
            repo_a,
            "express",
            "latest",
            &RefTarget::Version("4.18.2".into()),
        )
        .await;
        insert_ref(
            &pool,
            repo_a,
            "express",
            "next",
            &RefTarget::Version("5.0.0-beta".into()),
        )
        .await;
        insert_ref(
            &pool,
            repo_a,
            "lodash",
            "latest",
            &RefTarget::Version("4.17.21".into()),
        )
        .await;
        insert_ref(
            &pool,
            repo_b,
            "express",
            "latest",
            &RefTarget::Version("4.18.2".into()),
        )
        .await;

        let adapter = PgRefRegistry::new(pool.clone());
        let refs = adapter.list(repo_a, "express").await.unwrap();
        assert_eq!(refs.len(), 2, "only repo_a/express refs");
        // Ordered by ref_name.
        assert_eq!(refs[0].ref_name, "latest");
        assert_eq!(refs[1].ref_name, "next");
        for r in &refs {
            assert_eq!(r.repository_id, repo_a);
            assert_eq!(r.namespace, "express");
        }

        let refs_b = adapter.list(repo_b, "express").await.unwrap();
        assert_eq!(refs_b.len(), 1);
        assert_eq!(refs_b[0].repository_id, repo_b);

        let empty = adapter.list(repo_a, "nonexistent").await.unwrap();
        assert!(empty.is_empty());

        cleanup_repo(&pool, repo_a).await;
        cleanup_repo(&pool, repo_b).await;
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_target_content_hash() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let other_repo = seed_repo(&pool).await;

        let target_hash: hort_domain::types::ContentHash =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap();
        let other_hash: hort_domain::types::ContentHash =
            "a".repeat(64).parse().expect("64 hex chars");

        // Two refs in `repo` pointing at the same hash (different namespaces).
        insert_ref(
            &pool,
            repo,
            "library/nginx",
            "latest",
            &RefTarget::ContentHash(target_hash.clone()),
        )
        .await;
        insert_ref(
            &pool,
            repo,
            "library/nginx",
            "stable",
            &RefTarget::ContentHash(target_hash.clone()),
        )
        .await;
        // Different hash — must not show up.
        insert_ref(
            &pool,
            repo,
            "library/redis",
            "latest",
            &RefTarget::ContentHash(other_hash.clone()),
        )
        .await;
        // Same hash but a different repo — must not show up.
        insert_ref(
            &pool,
            other_repo,
            "library/nginx",
            "latest",
            &RefTarget::ContentHash(target_hash.clone()),
        )
        .await;
        // Version-kind ref with the raw hex in the version field —
        // must not accidentally match (two-column split).
        insert_ref(
            &pool,
            repo,
            "some-pkg",
            "latest",
            &RefTarget::Version(target_hash.as_ref().to_string()),
        )
        .await;

        let adapter = PgRefRegistry::new(pool.clone());
        let refs = adapter
            .find_by_target(repo, &RefTarget::ContentHash(target_hash.clone()))
            .await
            .unwrap();
        assert_eq!(refs.len(), 2);
        for r in &refs {
            assert_eq!(r.repository_id, repo);
            assert_eq!(r.target, RefTarget::ContentHash(target_hash.clone()));
        }

        cleanup_repo(&pool, repo).await;
        cleanup_repo(&pool, other_repo).await;
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_target_version() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        // Two dist-tags in different packages pointing at 1.2.3.
        insert_ref(
            &pool,
            repo,
            "express",
            "latest",
            &RefTarget::Version("1.2.3".into()),
        )
        .await;
        insert_ref(
            &pool,
            repo,
            "lodash",
            "latest",
            &RefTarget::Version("1.2.3".into()),
        )
        .await;
        // A different version value — must not show up.
        insert_ref(
            &pool,
            repo,
            "express",
            "next",
            &RefTarget::Version("2.0.0".into()),
        )
        .await;

        let adapter = PgRefRegistry::new(pool.clone());
        let refs = adapter
            .find_by_target(repo, &RefTarget::Version("1.2.3".into()))
            .await
            .unwrap();
        assert_eq!(refs.len(), 2);
        // Ordered by (namespace, ref_name).
        assert_eq!(refs[0].namespace, "express");
        assert_eq!(refs[1].namespace, "lodash");
        for r in &refs {
            assert_eq!(r.target, RefTarget::Version("1.2.3".into()));
        }

        cleanup_repo(&pool, repo).await;
    }
}
