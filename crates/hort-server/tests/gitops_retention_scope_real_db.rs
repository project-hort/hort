//! Integration test — a `kind: RetentionPolicy` envelope whose scope
//! names repositories reaches the projection with the ids resolved,
//! driven through the **real composition root**.
//!
//! # Why this test exists
//!
//! Two separate things have to hold for a retention policy an operator
//! authored to become a policy the sweep can read, and neither is
//! provable from the apply use case alone:
//!
//! 1. `scope: { Repos: [<metadata.name>, …] }` resolves to repository
//!    UUIDs, through the map the pipeline fills from `DesiredState`.
//! 2. `apply_config_from_dir` actually **wires** the retention apply
//!    slot. For the whole time that slot was builder-optional, this
//!    composition root never called the builder: envelopes were parsed,
//!    validated, warned about and dropped. A test that stubs the slot in
//!    cannot see that; only a test that goes through the production
//!    composition can.
//!
//! So this drives `hort_server::gitops_boot::apply_config_from_dir` over
//! a real config directory against a real database and reads the
//! resulting `retention_policy_projections` row back as raw SQL — the
//! far end of the pipeline, no mocks anywhere in between.
//!
//! # Skip-when-no-DB convention
//!
//! Mirrors `task_use_case_enqueue_real_db`: every test early-returns
//! when `DATABASE_URL` is unset, so the suite stays green without a
//! database. The pool is a per-test throwaway database
//! (`isolated_db_from`) — which isolates the *rows*, not the server:
//! creating and migrating that database is cluster-global work
//! (`CREATE DATABASE`, the migration set's `CREATE ROLE`, the shared
//! catalogs the stale-database sweeper walks), so each test also carries
//! the workspace-wide `#[serial(hort_pg_db)]` key.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-server --test gitops_retention_scope_real_db
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use serial_test::serial;
use sqlx::{PgPool, Row};
use tempfile::TempDir;
use uuid::Uuid;

use hort_app::use_cases::apply_config_use_case::UpstreamHostAllowlist;
use hort_server::config::{AuthConfig, StorageConfig};
use hort_server::gitops_boot::{apply_config_from_dir, GitopsBootError};

/// Connect to `DATABASE_URL`, on a throwaway database of this test's
/// own. Returns `None` when the env var is unset.
async fn isolated_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

fn write(dir: &Path, rel: &str, body: &str) {
    let full = dir.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).expect("create config subdir");
    }
    fs::write(full, body).expect("write config file");
}

fn repository_yaml(name: &str) -> String {
    format!(
        "apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: {name}
spec:
  name: {name}
  format: npm
  type: hosted
  storage: {{ backend: filesystem, path: /data/{name} }}
  isPublic: true
  replicationPriority: immediate
"
    )
}

fn retention_policy_yaml(name: &str, scope: &str) -> String {
    format!(
        "apiVersion: project-hort.de/v1
kind: RetentionPolicy
metadata:
  name: {name}
spec:
  predicate:
    AgeExceeds: 2592000
  scope: {scope}
"
    )
}

/// Run the production gitops apply over `config_dir`.
async fn apply(pool: &PgPool, config_dir: &Path) -> Result<(), GitopsBootError> {
    let storage_root = TempDir::new().expect("storage tempdir");
    let storage_cfg = StorageConfig::Filesystem {
        root: storage_root.path().to_path_buf(),
    };
    let (storage, _mirror) =
        hort_server::storage::build_with_mirror(&storage_cfg, None).expect("filesystem storage");
    apply_config_from_dir(
        pool,
        config_dir,
        &AuthConfig::Disabled,
        UpstreamHostAllowlist::Disabled,
        None,
        Arc::clone(&storage),
        storage_cfg.effective_backend(),
    )
    .await
    .map(|_status| ())
}

/// Read one active projection row's `scope` JSONB by policy name.
async fn projected_scope(pool: &PgPool, name: &str) -> serde_json::Value {
    sqlx::query(
        "SELECT scope FROM public.retention_policy_projections \
         WHERE name = $1 AND archived = false",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("the policy reached the projection")
    .get::<serde_json::Value, _>("scope")
}

async fn repository_id(pool: &PgPool, key: &str) -> Uuid {
    sqlx::query("SELECT id FROM public.repositories WHERE key = $1")
        .bind(key)
        .fetch_one(pool)
        .await
        .expect("repository row")
        .get::<Uuid, _>("id")
}

/// The acceptance case, end to end: names in, ids on the projection.
#[tokio::test]
#[serial(hort_pg_db)]
async fn named_repos_scope_lands_on_the_projection_as_uuids() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let dir = TempDir::new().expect("config tempdir");
    write(
        dir.path(),
        "repositories/npm-internal.yaml",
        &repository_yaml("npm-internal"),
    );
    write(
        dir.path(),
        "repositories/pypi-internal.yaml",
        &repository_yaml("pypi-internal"),
    );
    write(
        dir.path(),
        "retention/retain-named.yaml",
        &retention_policy_yaml("retain-named", "{ Repos: [pypi-internal, npm-internal] }"),
    );

    apply(&pool, dir.path()).await.expect("apply succeeds");

    let npm = repository_id(&pool, "npm-internal").await;
    let pypi = repository_id(&pool, "pypi-internal").await;
    let scope = projected_scope(&pool, "retain-named").await;

    assert_eq!(
        scope,
        serde_json::json!({ "Repos": [pypi.to_string(), npm.to_string()] }),
        "the projection must carry the resolved ids, in the authored order"
    );
}

/// The ordering guarantee on the **update** branch: a second apply that
/// introduces a brand-new repository and re-scopes an existing policy
/// onto it in the same bundle resolves cleanly. Resolution reads the map
/// the pipeline fills after the repository rows are written, so the new
/// name is already there.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_repository_declared_in_the_same_bundle_resolves_on_the_update_path() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let dir = TempDir::new().expect("config tempdir");
    write(
        dir.path(),
        "repositories/npm-internal.yaml",
        &repository_yaml("npm-internal"),
    );
    write(
        dir.path(),
        "retention/retain-named.yaml",
        &retention_policy_yaml("retain-named", "{ Repos: [npm-internal] }"),
    );
    apply(&pool, dir.path()).await.expect("first apply");

    // Second apply: a repository that did not exist a moment ago, and
    // the same policy re-scoped onto it.
    write(
        dir.path(),
        "repositories/npm-fresh.yaml",
        &repository_yaml("npm-fresh"),
    );
    write(
        dir.path(),
        "retention/retain-named.yaml",
        &retention_policy_yaml("retain-named", "{ Repos: [npm-fresh] }"),
    );
    apply(&pool, dir.path()).await.expect("second apply");

    let fresh = repository_id(&pool, "npm-fresh").await;
    assert_eq!(
        projected_scope(&pool, "retain-named").await,
        serde_json::json!({ "Repos": [fresh.to_string()] }),
        "the update path resolves a name declared in the same apply"
    );
}

/// An undeclared repository is rejected **before any write** — the
/// pre-flight validation stage, not a mid-apply crash — and the message
/// names the offending value.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_undeclared_repository_is_rejected_at_apply() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let dir = TempDir::new().expect("config tempdir");
    write(
        dir.path(),
        "repositories/npm-internal.yaml",
        &repository_yaml("npm-internal"),
    );
    write(
        dir.path(),
        "retention/retain-ghost.yaml",
        &retention_policy_yaml("retain-ghost", "{ Repos: [ghost-repo] }"),
    );

    let err = apply(&pool, dir.path())
        .await
        .expect_err("an undeclared repository must not apply");
    let rendered = err.to_string();
    assert!(
        matches!(err, GitopsBootError::PreflightValidate(_)),
        "rejection must land pre-write, got: {rendered}"
    );
    assert!(
        rendered.contains("ghost-repo"),
        "the message must name the offending value: {rendered}"
    );

    // Pre-write means pre-write: neither the policy nor the repository
    // it shipped alongside was written.
    let policies: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.retention_policy_projections")
            .fetch_one(&pool)
            .await
            .expect("count projections");
    assert_eq!(policies, 0, "a rejected bundle writes no policy");
}

/// A repository UUID is no longer a form this surface accepts: it is
/// read as a name, matches no declared repository, and is rejected.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_scope_still_written_as_uuids_is_rejected() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let dir = TempDir::new().expect("config tempdir");
    write(
        dir.path(),
        "repositories/npm-internal.yaml",
        &repository_yaml("npm-internal"),
    );
    let stale_id = Uuid::new_v4();
    write(
        dir.path(),
        "retention/retain-legacy.yaml",
        &retention_policy_yaml("retain-legacy", &format!("{{ Repos: ['{stale_id}'] }}")),
    );

    let rendered = apply(&pool, dir.path())
        .await
        .expect_err("a UUID names no repository")
        .to_string();
    assert!(
        rendered.contains(&stale_id.to_string()),
        "the message must name the offending value: {rendered}"
    );
}
