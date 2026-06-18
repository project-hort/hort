//! PostgreSQL read-side adapter for the `artifact_groups` +
//! `artifact_group_members` projection.
//!
//! Implements [`ArtifactGroupRepository`]. Writes live on the
//! (not-yet-shipped) `ArtifactGroupLifecyclePort`. This adapter does
//! reads only: `find_by_coords`,
//! `find_by_member`, `list_distinct_names`.
//!
//! # Coords canonicalisation
//!
//! The unique index on `(repository_id, coords_json)` is the group's
//! identity. JSONB comparison is logical (key-order-independent), but
//! differing payloads are different keys. To stay robust against callers
//! that forget to zero per-file fields, [`coords_to_canonical_json`] drops
//! `path` and `metadata` at adapter boundary — matching the contract
//! documented on
//! [`ArtifactGroup`](hort_domain::entities::artifact_group::ArtifactGroup).
//! Read-side lookups pass through the same canonicaliser, so a query built
//! from per-file coords hits the row stored under canonical coords.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use hort_domain::entities::artifact_group::{ArtifactGroup, ArtifactGroupMember};
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::artifact_group_repository::ArtifactGroupRepository;
use hort_domain::types::ArtifactCoords;

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`ArtifactGroupRepository`].
///
/// Thin wrapper over a `PgPool`; no per-instance state beyond the pool.
/// Construction is cheap (no I/O) — the pool itself governs connection
/// lifecycle.
pub struct PgArtifactGroupRepository {
    pool: PgPool,
}

impl PgArtifactGroupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// ---------------------------------------------------------------------------
// Canonicalisation
// ---------------------------------------------------------------------------

/// Build the canonical JSONB for an [`ArtifactCoords`].
///
/// Retains only the identity-forming fields — `name`, `name_as_published`,
/// `version`, `format`. `path` and `metadata` are per-file and MUST NOT
/// participate in the group key. See
/// [`ArtifactGroup`](hort_domain::entities::artifact_group::ArtifactGroup)
/// docstring for the full contract.
pub(crate) fn coords_to_canonical_json(coords: &ArtifactCoords) -> DomainResult<JsonValue> {
    // `RepositoryFormat` derives Serialize — using `to_value` keeps the
    // wire shape symmetric with the reverse mapping in `row_to_coords`.
    let format = serde_json::to_value(&coords.format).map_err(|e| {
        DomainError::Invariant(format!("failed to serialise RepositoryFormat to JSON: {e}"))
    })?;
    Ok(serde_json::json!({
        "name": coords.name,
        "name_as_published": coords.name_as_published,
        "version": coords.version,
        "format": format,
    }))
}

/// Reverse of [`coords_to_canonical_json`].
///
/// Reconstructs an [`ArtifactCoords`] from a stored `coords_json` row.
/// `path` is always empty and `metadata` is always `Null` under the
/// canonicalisation contract; if a row deviates the adapter surfaces
/// `DomainError::Invariant` rather than silently masking the corruption.
fn json_to_coords(value: JsonValue) -> DomainResult<ArtifactCoords> {
    let obj = match value {
        JsonValue::Object(map) => map,
        other => {
            return Err(DomainError::Invariant(format!(
                "artifact_groups.coords_json is not a JSON object: {other}"
            )));
        }
    };
    let name = obj
        .get("name")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| DomainError::Invariant("coords_json missing `name`".into()))?
        .to_owned();
    let name_as_published = obj
        .get("name_as_published")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| DomainError::Invariant("coords_json missing `name_as_published`".into()))?
        .to_owned();
    let version = match obj.get("version") {
        Some(JsonValue::String(s)) => Some(s.clone()),
        Some(JsonValue::Null) | None => None,
        other => {
            return Err(DomainError::Invariant(format!(
                "coords_json.version must be string or null, got {other:?}"
            )));
        }
    };
    let format_value = obj
        .get("format")
        .cloned()
        .ok_or_else(|| DomainError::Invariant("coords_json missing `format`".into()))?;
    let format: RepositoryFormat = serde_json::from_value(format_value).map_err(|e| {
        DomainError::Invariant(format!(
            "coords_json.format does not decode to RepositoryFormat: {e}"
        ))
    })?;
    Ok(ArtifactCoords {
        name,
        name_as_published,
        version,
        path: String::new(),
        format,
        metadata: JsonValue::Null,
    })
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

/// Wire shape for an `artifact_groups` row.
#[derive(Debug, FromRow)]
struct ArtifactGroupRow {
    id: Uuid,
    repository_id: Uuid,
    coords_json: JsonValue,
    primary_role: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Wire shape for an `artifact_group_members` row as projected by
/// [`fetch_members_for_group`]. `group_id` is omitted — the query filters
/// by a single group id, so the column would be a constant.
#[derive(Debug, FromRow)]
struct ArtifactGroupMemberRow {
    role: String,
    artifact_id: Uuid,
    added_at: DateTime<Utc>,
}

fn row_to_member(row: ArtifactGroupMemberRow) -> ArtifactGroupMember {
    ArtifactGroupMember {
        role: row.role,
        artifact_id: row.artifact_id,
        added_at: row.added_at,
    }
}

/// Translate a group row + the members for that group into a domain
/// [`ArtifactGroup`].
fn assemble_group(
    row: ArtifactGroupRow,
    members: Vec<ArtifactGroupMember>,
) -> DomainResult<ArtifactGroup> {
    let coords = json_to_coords(row.coords_json)?;
    Ok(ArtifactGroup {
        id: row.id,
        repository_id: row.repository_id,
        coords,
        primary_role: row.primary_role,
        members,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

// ---------------------------------------------------------------------------
// Shared fetching helpers
// ---------------------------------------------------------------------------

const SELECT_GROUP_COLS: &str = r#"
    id, repository_id, coords_json, primary_role,
    created_at, updated_at
"#;

const SELECT_MEMBER_COLS: &str = r#"
    role, artifact_id, added_at
"#;

/// Fetch all members of a single group, ordered by `added_at` so
/// consumers that care about arrival order get deterministic output.
async fn fetch_members_for_group(
    pool: &PgPool,
    group_id: Uuid,
) -> DomainResult<Vec<ArtifactGroupMember>> {
    let sql = format!(
        "SELECT {SELECT_MEMBER_COLS} FROM artifact_group_members \
         WHERE group_id = $1 \
         ORDER BY added_at, artifact_id"
    );
    let rows: Vec<ArtifactGroupMemberRow> = sqlx::query_as(&sql)
        .bind(group_id)
        .fetch_all(pool)
        .await
        .map_err(|e| map_sqlx_error(&e, "ArtifactGroupMember", &group_id.to_string()))?;
    Ok(rows.into_iter().map(row_to_member).collect())
}

// ---------------------------------------------------------------------------
// Port impl
// ---------------------------------------------------------------------------

impl ArtifactGroupRepository for PgArtifactGroupRepository {
    fn find_by_coords(
        &self,
        repo: Uuid,
        coords: &ArtifactCoords,
    ) -> BoxFuture<'_, DomainResult<Option<ArtifactGroup>>> {
        // Canonicalise at the adapter boundary so callers that forget to
        // zero per-file fields still hit the stored row.
        let canonical = coords_to_canonical_json(coords);
        Box::pin(async move {
            tracing::debug!(entity = "ArtifactGroup", %repo, "find_by_coords");
            let canonical = canonical?;
            let sql = format!(
                "SELECT {SELECT_GROUP_COLS} FROM artifact_groups \
                 WHERE repository_id = $1 AND coords_json = $2"
            );
            let row: Option<ArtifactGroupRow> = sqlx::query_as(&sql)
                .bind(repo)
                .bind(&canonical)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ArtifactGroup", &format!("coords/{repo}")))?;
            let Some(row) = row else {
                return Ok(None);
            };
            let members = fetch_members_for_group(&self.pool, row.id).await?;
            Ok(Some(assemble_group(row, members)?))
        })
    }

    fn find_by_member(
        &self,
        artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Option<ArtifactGroup>>> {
        Box::pin(async move {
            tracing::debug!(entity = "ArtifactGroup", %artifact_id, "find_by_member");
            // Two-step: look up the member row to find `group_id`, then
            // load the group + all its members. We can't join in one
            // query and keep all members because the member lookup
            // selects a single row.
            let member_sql = "SELECT group_id FROM artifact_group_members WHERE artifact_id = $1";
            let group_id: Option<(Uuid,)> = sqlx::query_as(member_sql)
                .bind(artifact_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ArtifactGroupMember", &artifact_id.to_string()))?;
            let Some((group_id,)) = group_id else {
                return Ok(None);
            };
            let group_sql =
                format!("SELECT {SELECT_GROUP_COLS} FROM artifact_groups WHERE id = $1");
            let row: Option<ArtifactGroupRow> = sqlx::query_as(&group_sql)
                .bind(group_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "ArtifactGroup", &group_id.to_string()))?;
            let Some(row) = row else {
                // Member row points at a group row that has been deleted
                // between the two queries. ON DELETE CASCADE should
                // prevent this under normal operation — surface it as
                // an invariant rather than a false "not found".
                return Err(DomainError::Invariant(format!(
                    "artifact_group_members.group_id {group_id} has no matching artifact_groups row"
                )));
            };
            let members = fetch_members_for_group(&self.pool, row.id).await?;
            Ok(Some(assemble_group(row, members)?))
        })
    }

    fn list_distinct_names(
        &self,
        repo: Uuid,
        primary_role: &str,
        after: Option<&str>,
        limit: u32,
    ) -> BoxFuture<'_, DomainResult<Vec<String>>> {
        let primary_role = primary_role.to_owned();
        // Empty-string sentinel for "from the start" — byte-stable under
        // COLLATE "C" because '' sorts before every non-empty string.
        let after = after.unwrap_or("").to_owned();
        Box::pin(async move {
            tracing::debug!(
                entity = "ArtifactGroup",
                %repo,
                primary_role = %primary_role,
                after = %after,
                limit,
                "list_distinct_names"
            );
            // DISTINCT + ORDER BY + LIMIT with the cursor comparison all
            // under COLLATE "C" so the expression index is usable and
            // ordering is byte-stable. The cast `$4::bigint` keeps LIMIT
            // typed — sqlx binds `u32` as INT4, which LIMIT also accepts,
            // but the explicit cast documents intent.
            // SELECT DISTINCT requires the ORDER BY expression to appear in
            // the select list — Postgres treats `(expr) COLLATE "C"` as a
            // distinct expression from `expr`. Move the COLLATE into SELECT
            // and reference the column alias in ORDER BY so both sides
            // agree on the collation-bound expression.
            let sql = r#"
                SELECT DISTINCT (coords_json->>'name') COLLATE "C" AS name
                FROM artifact_groups
                WHERE repository_id = $1
                  AND primary_role = $2
                  AND ((coords_json->>'name') COLLATE "C") > ($3 COLLATE "C")
                ORDER BY name ASC
                LIMIT $4
            "#;
            let rows: Vec<(Option<String>,)> = sqlx::query_as(sql)
                .bind(repo)
                .bind(&primary_role)
                .bind(&after)
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "ArtifactGroup", &format!("list_distinct_names/{repo}"))
                })?;
            // The JSONB `->>` operator returns NULL if the key is missing.
            // Under the canonicalisation contract `name` is required; a
            // row lacking it is corrupt — drop NULLs silently here and
            // let the DB schema and write path be the
            // enforcement boundary. (Alternative: bubble up Invariant —
            // but the enumeration endpoint should stay robust when one
            // row is corrupt.)
            Ok(rows.into_iter().filter_map(|(n,)| n).collect())
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

    // -- Compile-time port proof -------------------------------------------

    #[tokio::test]
    async fn pg_artifact_group_repository_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgArtifactGroupRepository::new(pool);
    }

    #[test]
    fn pg_artifact_group_repository_implements_port() {
        fn _assert_port<T: ArtifactGroupRepository>() {}
        _assert_port::<PgArtifactGroupRepository>();
    }

    // -- Canonicalisation round-trip ---------------------------------------

    fn sample_coords() -> ArtifactCoords {
        ArtifactCoords {
            name: "com.example:widget".into(),
            name_as_published: "com.example:widget".into(),
            version: Some("1.2.3".into()),
            path: String::new(),
            format: RepositoryFormat::Maven,
            metadata: JsonValue::Null,
        }
    }

    #[test]
    fn coords_to_canonical_json_retains_identity_fields() {
        let json = coords_to_canonical_json(&sample_coords()).unwrap();
        assert_eq!(json["name"], "com.example:widget");
        assert_eq!(json["name_as_published"], "com.example:widget");
        assert_eq!(json["version"], "1.2.3");
        assert!(json.get("path").is_none(), "path MUST NOT appear");
        assert!(json.get("metadata").is_none(), "metadata MUST NOT appear");
    }

    #[test]
    fn coords_to_canonical_json_drops_per_file_fields() {
        // Caller passes coords with non-empty path / metadata — adapter
        // MUST still produce the canonical key.
        let mut c = sample_coords();
        c.path = "some/file.jar".into();
        c.metadata = serde_json::json!({"extra": true});
        let canonical = coords_to_canonical_json(&c).unwrap();
        let clean = coords_to_canonical_json(&sample_coords()).unwrap();
        assert_eq!(canonical, clean);
    }

    #[test]
    fn coords_to_canonical_json_nullable_version() {
        let mut c = sample_coords();
        c.version = None;
        let json = coords_to_canonical_json(&c).unwrap();
        assert!(json["version"].is_null());
    }

    #[test]
    fn coords_to_canonical_json_roundtrip_via_json_to_coords() {
        let original = sample_coords();
        let j = coords_to_canonical_json(&original).unwrap();
        let back = json_to_coords(j).unwrap();
        assert_eq!(back.name, original.name);
        assert_eq!(back.name_as_published, original.name_as_published);
        assert_eq!(back.version, original.version);
        assert_eq!(back.format, original.format);
        assert_eq!(back.path, String::new());
        assert!(back.metadata.is_null());
    }

    #[test]
    fn coords_to_canonical_json_roundtrip_null_version() {
        let mut original = sample_coords();
        original.version = None;
        let j = coords_to_canonical_json(&original).unwrap();
        let back = json_to_coords(j).unwrap();
        assert_eq!(back.version, None);
    }

    #[test]
    fn coords_to_canonical_json_other_format() {
        let mut c = sample_coords();
        c.format = RepositoryFormat::Other("custom".into());
        let j = coords_to_canonical_json(&c).unwrap();
        let back = json_to_coords(j).unwrap();
        assert_eq!(back.format, RepositoryFormat::Other("custom".into()));
    }

    // -- json_to_coords error paths ----------------------------------------

    #[test]
    fn json_to_coords_non_object_is_invariant() {
        let err = json_to_coords(JsonValue::String("hi".into())).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)), "got {err}");
    }

    #[test]
    fn json_to_coords_missing_name_is_invariant() {
        let v = serde_json::json!({
            "name_as_published": "x",
            "version": "1",
            "format": "maven",
        });
        let err = json_to_coords(v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn json_to_coords_missing_name_as_published_is_invariant() {
        let v = serde_json::json!({
            "name": "x",
            "version": "1",
            "format": "maven",
        });
        let err = json_to_coords(v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn json_to_coords_missing_format_is_invariant() {
        let v = serde_json::json!({
            "name": "x",
            "name_as_published": "x",
            "version": "1",
        });
        let err = json_to_coords(v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn json_to_coords_bad_version_type_is_invariant() {
        let v = serde_json::json!({
            "name": "x",
            "name_as_published": "x",
            "version": 42,
            "format": "maven",
        });
        let err = json_to_coords(v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn json_to_coords_bad_format_is_invariant() {
        let v = serde_json::json!({
            "name": "x",
            "name_as_published": "x",
            "version": null,
            "format": 42,
        });
        let err = json_to_coords(v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // -- assemble_group ----------------------------------------------------

    #[test]
    fn assemble_group_preserves_members_order() {
        let row = ArtifactGroupRow {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            coords_json: coords_to_canonical_json(&sample_coords()).unwrap(),
            primary_role: "jar".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let m1 = ArtifactGroupMember {
            role: "jar".into(),
            artifact_id: Uuid::new_v4(),
            added_at: Utc::now(),
        };
        let m2 = ArtifactGroupMember {
            role: "pom".into(),
            artifact_id: Uuid::new_v4(),
            added_at: Utc::now(),
        };
        let g = assemble_group(row, vec![m1.clone(), m2.clone()]).unwrap();
        assert_eq!(g.members.len(), 2);
        assert_eq!(g.members[0], m1);
        assert_eq!(g.members[1], m2);
    }

    #[test]
    fn assemble_group_propagates_invalid_json() {
        let row = ArtifactGroupRow {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            coords_json: JsonValue::String("not-an-object".into()),
            primary_role: "jar".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let err = assemble_group(row, vec![]).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn row_to_member_copies_all_fields() {
        let now = Utc::now();
        let aid = Uuid::new_v4();
        let row = ArtifactGroupMemberRow {
            role: "layer".into(),
            artifact_id: aid,
            added_at: now,
        };
        let m = row_to_member(row);
        assert_eq!(m.role, "layer");
        assert_eq!(m.artifact_id, aid);
        assert_eq!(m.added_at, now);
    }

    // -----------------------------------------------------------------
    // DB-backed integration tests. Skipped (noisy "pass") when
    // `DATABASE_URL` is unset — mirrors `ref_registry_repo.rs`.
    // -----------------------------------------------------------------

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
        let key = format!("it-groups-{}", id.simple());
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

    /// Seed an `artifacts` row so we have a valid FK for `artifact_group_members`.
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
        .bind(path) // use path as a unique `name` too
        .bind(path)
        .execute(pool)
        .await
        .expect("seed artifact insert");
        id
    }

    /// Seed an `artifact_groups` row directly (no write port yet).
    async fn seed_group(
        pool: &PgPool,
        repo: Uuid,
        coords: &ArtifactCoords,
        primary_role: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let canonical = coords_to_canonical_json(coords).expect("canonicalise");
        sqlx::query(
            r#"INSERT INTO artifact_groups (id, repository_id, coords_json, primary_role)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(id)
        .bind(repo)
        .bind(&canonical)
        .bind(primary_role)
        .execute(pool)
        .await
        .expect("seed artifact_groups insert");
        id
    }

    /// Seed an `artifact_group_members` row directly.
    async fn seed_member(pool: &PgPool, group_id: Uuid, role: &str, artifact_id: Uuid) {
        sqlx::query(
            r#"INSERT INTO artifact_group_members (group_id, role, artifact_id)
               VALUES ($1, $2, $3)"#,
        )
        .bind(group_id)
        .bind(role)
        .bind(artifact_id)
        .execute(pool)
        .await
        .expect("seed artifact_group_members insert");
    }

    fn maven_coords(name: &str, version: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.into(),
            name_as_published: name.into(),
            version: Some(version.into()),
            path: String::new(),
            format: RepositoryFormat::Maven,
            metadata: JsonValue::Null,
        }
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_coords_roundtrip_for_seeded_group() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let coords = maven_coords("com.example:widget", "1.2.3");
        let group_id = seed_group(&pool, repo, &coords, "jar").await;
        let artifact = seed_artifact(&pool, repo, "com.example/widget/1.2.3/widget.jar").await;
        seed_member(&pool, group_id, "jar", artifact).await;

        let adapter = PgArtifactGroupRepository::new(pool.clone());

        // Lookup with canonical coords — hits.
        let got = adapter
            .find_by_coords(repo, &coords)
            .await
            .expect("find_by_coords")
            .expect("group exists");
        assert_eq!(got.id, group_id);
        assert_eq!(got.repository_id, repo);
        assert_eq!(got.primary_role, "jar");
        assert_eq!(got.coords.name, coords.name);
        assert_eq!(got.coords.version, coords.version);
        assert_eq!(got.members.len(), 1);
        assert_eq!(got.members[0].role, "jar");
        assert_eq!(got.members[0].artifact_id, artifact);

        // Lookup with NON-canonical coords (path + metadata populated) —
        // adapter canonicalises at the boundary, same row hits.
        let mut dirty = coords.clone();
        dirty.path = "com.example/widget/1.2.3/widget.jar".into();
        dirty.metadata = serde_json::json!({"extra": "ignored"});
        let got_dirty = adapter
            .find_by_coords(repo, &dirty)
            .await
            .expect("find_by_coords (dirty)")
            .expect("group exists via canonicalised path");
        assert_eq!(got_dirty.id, group_id);

        // Miss — different version.
        let other = maven_coords("com.example:widget", "9.9.9");
        let miss = adapter.find_by_coords(repo, &other).await.unwrap();
        assert!(miss.is_none());

        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn find_by_member_reverse_lookup() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let coords = maven_coords("com.example:widget", "1.2.3");
        let group_id = seed_group(&pool, repo, &coords, "jar").await;
        let jar = seed_artifact(&pool, repo, "widget-1.2.3.jar").await;
        let pom = seed_artifact(&pool, repo, "widget-1.2.3.pom").await;
        seed_member(&pool, group_id, "jar", jar).await;
        seed_member(&pool, group_id, "pom", pom).await;

        let adapter = PgArtifactGroupRepository::new(pool.clone());

        // Both members map back to the same group.
        for aid in [jar, pom] {
            let g = adapter
                .find_by_member(aid)
                .await
                .unwrap()
                .expect("member resolves to group");
            assert_eq!(g.id, group_id);
            assert_eq!(g.members.len(), 2, "both members visible on each lookup");
        }

        // Artifact outside any group.
        let orphan = seed_artifact(&pool, repo, "orphan-1.0.0.tar.gz").await;
        let miss = adapter.find_by_member(orphan).await.unwrap();
        assert!(miss.is_none());

        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn list_distinct_names_paginates_byte_stably() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        // COLLATE "C" sorts uppercase before lowercase (B < a < g < z in byte order).
        // Seeding mixed case guarantees any accidental ICU collation
        // would resort these differently and the cursor test would fail.
        for name in ["alpha", "Beta", "gamma", "zeta"] {
            let _ = seed_group(&pool, repo, &maven_coords(name, "1.0.0"), "manifest").await;
        }
        // Same name, different primary_role — must not leak into the
        // primary_role = "manifest" filter.
        let _ = seed_group(&pool, repo, &maven_coords("other-role", "1.0.0"), "jar").await;

        let adapter = PgArtifactGroupRepository::new(pool.clone());

        // Page 1, limit 2, cursor = None → ["Beta", "alpha"] under COLLATE "C".
        let page1 = adapter
            .list_distinct_names(repo, "manifest", None, 2)
            .await
            .unwrap();
        assert_eq!(page1, vec!["Beta".to_string(), "alpha".to_string()]);

        // Page 2, cursor = last of page 1.
        let page2 = adapter
            .list_distinct_names(repo, "manifest", Some(page1.last().unwrap()), 2)
            .await
            .unwrap();
        assert_eq!(page2, vec!["gamma".to_string(), "zeta".to_string()]);

        // Page 3 — no more rows.
        let page3 = adapter
            .list_distinct_names(repo, "manifest", Some(page2.last().unwrap()), 2)
            .await
            .unwrap();
        assert!(page3.is_empty());

        // Filter by a different primary_role — only "other-role" shows up.
        let other = adapter
            .list_distinct_names(repo, "jar", None, 10)
            .await
            .unwrap();
        assert_eq!(other, vec!["other-role".to_string()]);

        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn two_files_one_group_m3_guard() {
        // M3 regression test: seed a group row; try to insert a second
        // row with the same (repository_id, coords_json) — unique index
        // must reject. Then add two members with different roles to the
        // ONE group; both must land under that single row on
        // `find_by_coords`.
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let coords = maven_coords("com.example:lib", "2.0.0");

        // First insert succeeds.
        let group_id = seed_group(&pool, repo, &coords, "jar").await;

        // Second insert with the SAME (repo, coords_json) must fail the
        // unique constraint — even though the logical canonical JSONB
        // may be byte-differently serialised on the client, Postgres
        // compares logically.
        let canonical = coords_to_canonical_json(&coords).unwrap();
        let duplicate = sqlx::query(
            r#"INSERT INTO artifact_groups (id, repository_id, coords_json, primary_role)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(Uuid::new_v4())
        .bind(repo)
        .bind(&canonical)
        .bind("jar")
        .execute(&pool)
        .await;
        assert!(
            duplicate.is_err(),
            "unique (repository_id, coords_json) must reject duplicates, got Ok"
        );
        let err = duplicate.unwrap_err().to_string();
        assert!(
            err.to_lowercase().contains("duplicate") || err.to_lowercase().contains("unique"),
            "expected unique-violation error, got: {err}"
        );

        // Now add two members with different roles — both must belong to
        // the ONE group.
        let jar = seed_artifact(&pool, repo, "lib-2.0.0.jar").await;
        let pom = seed_artifact(&pool, repo, "lib-2.0.0.pom").await;
        seed_member(&pool, group_id, "jar", jar).await;
        seed_member(&pool, group_id, "pom", pom).await;

        let adapter = PgArtifactGroupRepository::new(pool.clone());
        let got = adapter
            .find_by_coords(repo, &coords)
            .await
            .unwrap()
            .expect("group exists");
        assert_eq!(got.id, group_id);
        assert_eq!(
            got.members.len(),
            2,
            "one group row but two members with distinct roles"
        );
        let roles: Vec<String> = got.members.iter().map(|m| m.role.clone()).collect();
        assert!(roles.contains(&"jar".into()));
        assert!(roles.contains(&"pom".into()));

        cleanup_repo(&pool, repo).await;
    }
}
