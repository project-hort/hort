//! `PgCurationDecisionsRepository` integration tests.
//!
//! Exercises the curation event-log query end-to-end against a real
//! Postgres. Each acceptance scenario from the backlog gets its own
//! `#[tokio::test]`.
//!
//! `#[serial(hort_pg_db)]` is **mandatory** on every test that acquires
//! a real DB connection — CLAUDE.md "DB-backed test isolation
//! (parallel-safety contract)". Adding a maybe_pool() test without
//! the serial key reintroduces the identity-shifting flake fixed in
//! ed79360a.
//!
//! DATABASE_URL-gated; every test early-returns silently when the env
//! var is unset so dev environments without a database keep the suite
//! green. Mirrors the convention in
//! `crates/hort-adapters-postgres/tests/curation_queue_repository.rs`.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test curation_decisions_repository
//! ```

#![allow(clippy::expect_used)]

use std::env;

use chrono::{Duration, Utc};
use serde_json::json;
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::curation_decisions_repository::PgCurationDecisionsRepository;
use hort_domain::ports::curation_decisions_repository::{
    CurationDecisionFilter, CurationDecisionKind, CurationDecisionsRepository,
};

/// Connect via per-test isolation, run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset.
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");
    Some(pool)
}

/// Seed a `repositories` row with the given `format` and return its id.
async fn seed_repo(pool: &PgPool, format_literal: &'static str) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-curation-decisions-{}", id.simple());
    let format_sql = format!("'{format_literal}'::repository_format");
    let sql = format!(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $3,
               {format_sql},
               'hosted'::repository_type,
               'filesystem', $4,
               'local_only'::replication_priority
           )"#
    );
    sqlx::query(&sql)
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .execute(pool)
        .await
        .expect("seed_repo");
    id
}

/// Seed an artifact row.
async fn seed_artifact(pool: &PgPool, repo: Uuid, name: &str, version: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key = id.simple().to_string();
    let sha256 = format!("{key}{key}");
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key
           ) VALUES (
               $1, $2, $3, $3, $4, $5,
               0, $6, 'application/octet-stream', $6
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(name)
    .bind(version)
    .bind(format!("{name}/{version}/{key}.tgz"))
    .bind(&sha256)
    .execute(pool)
    .await
    .expect("seed_artifact");
    id
}

/// Seed a non-archived policy_projections row so exclusion FK can attach.
async fn seed_policy(pool: &PgPool) -> Uuid {
    let policy_id = Uuid::new_v4();
    let name = format!("it-curation-decisions-policy-{}", policy_id.simple());
    let scope = json!({ "Global": null });
    sqlx::query(
        r#"INSERT INTO public.policy_projections (
               policy_id, name, scope, severity_threshold,
               rescan_interval_hours, quarantine_duration_secs,
               require_approval, archived,
               stream_version
           ) VALUES (
               $1, $2, $3, 'high',
               24, 86400,
               false, false,
               1
           )"#,
    )
    .bind(policy_id)
    .bind(&name)
    .bind(&scope)
    .execute(pool)
    .await
    .expect("seed policy_projections row");
    policy_id
}

/// Position-dependent unique 32-byte hash so multiple events on the
/// same stream don't collide on the chain-step check. We don't verify
/// the chain in this test; pure structural shape.
fn fake_hash(stream_position: i64, salt: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = stream_position as u8;
    h[1] = salt;
    h
}

/// Seed an event with a fully-controlled envelope shape.
///
/// `actor_type` should be one of `'api'` (with non-None
/// `actor_id`), `'system'`/`'timer'`/`'retention_scheduler'` (with
/// None `actor_id`), or `'gitops'` (with non-None
/// source_file/spec_digest — not exercised in these tests). The DB
/// `chk_actor_id` constraint enforces shape; the helper requires the
/// caller pass a coherent pair.
#[allow(clippy::too_many_arguments)]
async fn seed_event(
    pool: &PgPool,
    stream_id: &str,
    stream_category: &str,
    stream_position: i64,
    event_type: &str,
    event_data: serde_json::Value,
    actor_type: &str,
    actor_id: Option<Uuid>,
    correlation_id: Uuid,
) -> Uuid {
    let event_id = Uuid::new_v4();
    let salt = (event_id.as_u128() >> 64) as u8;
    sqlx::query(
        r#"INSERT INTO events
              (event_id, stream_id, stream_category, stream_position,
               event_type, event_version, event_data, correlation_id,
               actor_type, actor_id, prev_event_hash, event_hash)
            VALUES ($1, $2, $3, $4, $5, 1,
                    $6, $7, $8, $9, $10, $11)"#,
    )
    .bind(event_id)
    .bind(stream_id)
    .bind(stream_category)
    .bind(stream_position)
    .bind(event_type)
    .bind(&event_data)
    .bind(correlation_id)
    .bind(actor_type)
    .bind(actor_id)
    .bind([0u8; 32].as_slice())
    .bind(fake_hash(stream_position, salt).as_slice())
    .execute(pool)
    .await
    .expect("seed event");
    event_id
}

/// Seed a curator-issued `ArtifactReleased` event (`released_by =
/// "Curator"`, payload-side discriminator).
async fn seed_curator_waive(
    pool: &PgPool,
    artifact_id: Uuid,
    curator_id: Uuid,
    correlation_id: Uuid,
    justification: &str,
) -> Uuid {
    let stream_id = format!("artifact-{artifact_id}");
    let event_data = json!({
        "type": "ArtifactReleased",
        "data": {
            "artifact_id": artifact_id,
            "released_by": "Curator",
            "released_by_user_id": curator_id,
            "justification": justification,
        }
    });
    seed_event(
        pool,
        &stream_id,
        "artifact",
        0,
        "ArtifactReleased",
        event_data,
        "api",
        Some(curator_id),
        correlation_id,
    )
    .await
}

/// Seed a curator-issued `ArtifactRejected` event (`rejected_by =
/// {"Curator": {"curator_id": ...}}`, payload-side discriminator).
async fn seed_curator_block(
    pool: &PgPool,
    artifact_id: Uuid,
    curator_id: Uuid,
    correlation_id: Uuid,
    justification: &str,
) -> Uuid {
    let stream_id = format!("artifact-{artifact_id}");
    let event_data = json!({
        "type": "ArtifactRejected",
        "data": {
            "artifact_id": artifact_id,
            "rejected_by": { "Curator": { "curator_id": curator_id } },
            "reason": justification,
        }
    });
    seed_event(
        pool,
        &stream_id,
        "artifact",
        0,
        "ArtifactRejected",
        event_data,
        "api",
        Some(curator_id),
        correlation_id,
    )
    .await
}

/// Seed a scanner-issued `ArtifactRejected` event — MUST NOT match the
/// curator discriminator filter.
async fn seed_scanner_reject(pool: &PgPool, artifact_id: Uuid) -> Uuid {
    let stream_id = format!("artifact-{artifact_id}");
    let event_data = json!({
        "type": "ArtifactRejected",
        "data": {
            "artifact_id": artifact_id,
            "rejected_by": "Scanner",
            "reason": "scanner-rejection",
        }
    });
    seed_event(
        pool,
        &stream_id,
        "artifact",
        0,
        "ArtifactRejected",
        event_data,
        "system",
        None,
        Uuid::new_v4(),
    )
    .await
}

/// Seed an `ExclusionAdded` event with the requested envelope actor
/// shape. `actor_type='api' AND actor_id=Some(...)` is the curator
/// path; `actor_type='system' AND actor_id=None` is the
/// system-driven path (e.g. retention housekeeping) that must NOT
/// match the curator filter.
///
/// `stream_position` lets multiple events sit on the same policy
/// stream without colliding on the (stream_id, stream_position)
/// unique index.
#[allow(clippy::too_many_arguments)]
async fn seed_exclusion_added(
    pool: &PgPool,
    policy_id: Uuid,
    exclusion_id: Uuid,
    cve_id: &str,
    actor_type: &str,
    actor_id: Option<Uuid>,
    reason: &str,
    stream_position: i64,
) -> Uuid {
    let stream_id = format!("policy-{policy_id}");
    let event_data = json!({
        "type": "ExclusionAdded",
        "data": {
            "policy_id": policy_id,
            "exclusion_id": exclusion_id,
            "cve_id": cve_id,
            "package_pattern": null,
            "scope": { "Global": null },
            "reason": reason,
            "expires_at": null,
        }
    });
    seed_event(
        pool,
        &stream_id,
        "policy",
        stream_position,
        "ExclusionAdded",
        event_data,
        actor_type,
        actor_id,
        Uuid::new_v4(),
    )
    .await
}

/// Seed an `ExclusionRemoved` event. Same envelope-actor split as
/// `seed_exclusion_added`.
#[allow(clippy::too_many_arguments)]
async fn seed_exclusion_removed(
    pool: &PgPool,
    policy_id: Uuid,
    exclusion_id: Uuid,
    actor_type: &str,
    actor_id: Option<Uuid>,
    reason: &str,
    stream_position: i64,
) -> Uuid {
    let stream_id = format!("policy-{policy_id}");
    let event_data = json!({
        "type": "ExclusionRemoved",
        "data": {
            "policy_id": policy_id,
            "exclusion_id": exclusion_id,
            "reason": reason,
        }
    });
    seed_event(
        pool,
        &stream_id,
        "policy",
        stream_position,
        "ExclusionRemoved",
        event_data,
        actor_type,
        actor_id,
        Uuid::new_v4(),
    )
    .await
}

/// Seed an `exclusion_projections` row so ExclusionRemoved can
/// resolve `cve_id`.
async fn seed_exclusion_projection(
    pool: &PgPool,
    exclusion_id: Uuid,
    policy_id: Uuid,
    cve_id: &str,
) {
    let scope = json!({ "Global": null });
    sqlx::query(
        r#"INSERT INTO public.exclusion_projections
              (exclusion_id, policy_id, cve_id, scope, reason)
            VALUES ($1, $2, $3, $4, 'integration test')"#,
    )
    .bind(exclusion_id)
    .bind(policy_id)
    .bind(cve_id)
    .bind(scope)
    .execute(pool)
    .await
    .expect("seed exclusion_projections row");
}

/// Cascade-delete everything seeded under the test repo (artifacts +
/// scan_findings) and the test policy (exclusion_projections).
async fn cleanup_repo(pool: &PgPool, repo_id: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

async fn cleanup_policy(pool: &PgPool, policy_id: Uuid) {
    let _ = sqlx::query("DELETE FROM policy_projections WHERE policy_id = $1")
        .bind(policy_id)
        .execute(pool)
        .await;
}

// ---------------------------------------------------------------------------
// Test 1 — happy path: each `CurationDecisionKind` variant filters to
// the matching row class.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_decisions_kind_filter_waive() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool, "npm").await;
    let policy = seed_policy(&pool).await;
    let artifact = seed_artifact(&pool, repo, "p", "1.0").await;
    let curator = Uuid::new_v4();

    let waive_id = seed_curator_waive(
        &pool,
        artifact,
        curator,
        Uuid::new_v4(),
        "false positive after review",
    )
    .await;
    // Block — different kind, must NOT surface under Waive filter.
    let artifact_blk = seed_artifact(&pool, repo, "p", "2.0").await;
    let _ = seed_curator_block(&pool, artifact_blk, curator, Uuid::new_v4(), "block reason").await;

    let adapter = PgCurationDecisionsRepository::new(pool.clone());
    let rows = adapter
        .list_decisions(CurationDecisionFilter {
            kind: Some(CurationDecisionKind::Waive),
            ..CurationDecisionFilter::default()
        })
        .await
        .expect("list_decisions");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.event_id).collect();
    assert!(
        ids.contains(&waive_id),
        "Waive filter must surface ArtifactReleased curator event"
    );
    // No Block / Exclude rows in the filtered output.
    assert!(rows.iter().all(|r| r.kind == CurationDecisionKind::Waive));

    cleanup_repo(&pool, repo).await;
    cleanup_policy(&pool, policy).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_decisions_kind_filter_block() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool, "npm").await;
    let policy = seed_policy(&pool).await;
    let artifact = seed_artifact(&pool, repo, "p", "1.0").await;
    let curator = Uuid::new_v4();

    let block_id =
        seed_curator_block(&pool, artifact, curator, Uuid::new_v4(), "manual rejection").await;

    let adapter = PgCurationDecisionsRepository::new(pool.clone());
    let rows = adapter
        .list_decisions(CurationDecisionFilter {
            kind: Some(CurationDecisionKind::Block),
            ..CurationDecisionFilter::default()
        })
        .await
        .expect("list_decisions");

    let row = rows
        .iter()
        .find(|r| r.event_id == block_id)
        .expect("curator block must surface");
    assert_eq!(row.kind, CurationDecisionKind::Block);
    assert_eq!(row.actor_id, curator);
    assert_eq!(row.artifact_id, Some(artifact));
    assert_eq!(row.policy_id, None);
    assert_eq!(row.cve_id, None);

    cleanup_repo(&pool, repo).await;
    cleanup_policy(&pool, policy).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_decisions_kind_filter_exclude_finding() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let policy = seed_policy(&pool).await;
    let exclusion_id = Uuid::new_v4();
    let curator = Uuid::new_v4();

    let event_id = seed_exclusion_added(
        &pool,
        policy,
        exclusion_id,
        "CVE-2026-1234",
        "api",
        Some(curator),
        "false positive",
        0,
    )
    .await;

    let adapter = PgCurationDecisionsRepository::new(pool.clone());
    let rows = adapter
        .list_decisions(CurationDecisionFilter {
            kind: Some(CurationDecisionKind::ExcludeFinding),
            ..CurationDecisionFilter::default()
        })
        .await
        .expect("list_decisions");

    let row = rows
        .iter()
        .find(|r| r.event_id == event_id)
        .expect("curator ExclusionAdded must surface");
    assert_eq!(row.kind, CurationDecisionKind::ExcludeFinding);
    assert_eq!(row.actor_id, curator);
    assert_eq!(row.policy_id, Some(policy));
    assert_eq!(row.cve_id.as_deref(), Some("CVE-2026-1234"));
    assert_eq!(row.artifact_id, None);

    cleanup_policy(&pool, policy).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_decisions_kind_filter_unexclude_finding() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let policy = seed_policy(&pool).await;
    let exclusion_id = Uuid::new_v4();
    let curator = Uuid::new_v4();
    let cve = "CVE-2026-9999";

    // ExclusionRemoved payload carries only policy_id + exclusion_id;
    // cve_id is resolved via the exclusion_projections LEFT JOIN.
    seed_exclusion_projection(&pool, exclusion_id, policy, cve).await;
    let event_id = seed_exclusion_removed(
        &pool,
        policy,
        exclusion_id,
        "api",
        Some(curator),
        "re-evaluation done",
        0,
    )
    .await;

    let adapter = PgCurationDecisionsRepository::new(pool.clone());
    let rows = adapter
        .list_decisions(CurationDecisionFilter {
            kind: Some(CurationDecisionKind::UnexcludeFinding),
            ..CurationDecisionFilter::default()
        })
        .await
        .expect("list_decisions");

    let row = rows
        .iter()
        .find(|r| r.event_id == event_id)
        .expect("curator ExclusionRemoved must surface");
    assert_eq!(row.kind, CurationDecisionKind::UnexcludeFinding);
    assert_eq!(row.actor_id, curator);
    assert_eq!(row.policy_id, Some(policy));
    // cve_id resolved via exclusion_projections join.
    assert_eq!(row.cve_id.as_deref(), Some(cve));
    assert_eq!(row.artifact_id, None);

    cleanup_policy(&pool, policy).await;
}

// ---------------------------------------------------------------------------
// Test 2 — envelope-side vs payload-side discrimination (load-bearing).
// A user-actor ExclusionAdded surfaces under the kind filter; a
// system-actor ExclusionAdded must NOT surface (envelope-side
// `actor_type = 'api'` discriminator).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_decisions_excludes_system_actor_exclusion_added() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let policy = seed_policy(&pool).await;
    let curator = Uuid::new_v4();
    let user_exclusion = Uuid::new_v4();
    let system_exclusion = Uuid::new_v4();

    // User actor → surfaces.
    let user_event = seed_exclusion_added(
        &pool,
        policy,
        user_exclusion,
        "CVE-USER-1",
        "api",
        Some(curator),
        "user-reason",
        0,
    )
    .await;
    // System actor → MUST NOT surface (envelope-side discriminator
    // rejects). Different stream_position to avoid colliding on the
    // (stream_id, stream_position) unique index — both events sit on
    // the same `policy-<id>` stream.
    let _system_event = seed_exclusion_added(
        &pool,
        policy,
        system_exclusion,
        "CVE-SYS-1",
        "system",
        None,
        "system-reason",
        1,
    )
    .await;

    let adapter = PgCurationDecisionsRepository::new(pool.clone());
    let rows = adapter
        .list_decisions(CurationDecisionFilter {
            kind: Some(CurationDecisionKind::ExcludeFinding),
            ..CurationDecisionFilter::default()
        })
        .await
        .expect("list_decisions");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.event_id).collect();
    assert!(
        ids.contains(&user_event),
        "user-actor ExclusionAdded must surface"
    );
    assert!(
        !ids.contains(&_system_event),
        "system-actor ExclusionAdded must NOT surface under curator-decision filter"
    );

    cleanup_policy(&pool, policy).await;
}

// ---------------------------------------------------------------------------
// Test 3 — `ArtifactRejected` non-curator (Scanner) does NOT surface
// under the curator filter (payload-side discriminator).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_decisions_excludes_scanner_rejected_artifact() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool, "npm").await;
    let curator = Uuid::new_v4();
    let artifact_curator = seed_artifact(&pool, repo, "p", "1.0").await;
    let artifact_scanner = seed_artifact(&pool, repo, "p", "2.0").await;

    let curator_block = seed_curator_block(
        &pool,
        artifact_curator,
        curator,
        Uuid::new_v4(),
        "curator block",
    )
    .await;
    let scanner_reject = seed_scanner_reject(&pool, artifact_scanner).await;

    let adapter = PgCurationDecisionsRepository::new(pool.clone());
    let rows = adapter
        .list_decisions(CurationDecisionFilter {
            kind: Some(CurationDecisionKind::Block),
            ..CurationDecisionFilter::default()
        })
        .await
        .expect("list_decisions");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.event_id).collect();
    assert!(
        ids.contains(&curator_block),
        "curator-block must surface under Block filter"
    );
    assert!(
        !ids.contains(&scanner_reject),
        "scanner-rejected must NOT surface under Block filter (payload-side curator discriminator)"
    );

    cleanup_repo(&pool, repo).await;
}

// ---------------------------------------------------------------------------
// Test 4 — `--since` cutoff at SQL level.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_decisions_since_filter_applies_at_sql_level() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool, "npm").await;
    let curator = Uuid::new_v4();

    // Default helper inserts with `stored_at = now()`. Old event lands
    // in the present.
    let artifact_old = seed_artifact(&pool, repo, "p", "1.0").await;
    let _old_event =
        seed_curator_waive(&pool, artifact_old, curator, Uuid::new_v4(), "old waive").await;

    // Cutoff far enough in the future that the default `now()` stored_at
    // is strictly before it.
    let cutoff = Utc::now() + Duration::days(365);

    // Seed a SECOND event with a controlled future `stored_at` via a
    // direct INSERT path (the default helper uses `now()`). The
    // events-immutability trigger is BEFORE UPDATE / DELETE only —
    // INSERT with an explicit stored_at is allowed. This pattern is
    // test-only fixture setup.
    let future_event_id = Uuid::new_v4();
    let artifact_future = seed_artifact(&pool, repo, "p", "3.0").await;
    let stream_id_future = format!("artifact-{artifact_future}");
    let future_data = json!({
        "type": "ArtifactReleased",
        "data": {
            "artifact_id": artifact_future,
            "released_by": "Curator",
            "released_by_user_id": curator,
            "justification": "future waive",
        }
    });
    sqlx::query(
        r#"INSERT INTO events
              (event_id, stream_id, stream_category, stream_position,
               event_type, event_version, event_data, correlation_id,
               actor_type, actor_id, stored_at,
               prev_event_hash, event_hash)
            VALUES ($1, $2, 'artifact', 0, 'ArtifactReleased', 1,
                    $3, $4, 'api', $5, $6,
                    $7, $8)"#,
    )
    .bind(future_event_id)
    .bind(&stream_id_future)
    .bind(&future_data)
    .bind(Uuid::new_v4())
    .bind(curator)
    .bind(Utc::now() + Duration::days(400))
    .bind([0u8; 32].as_slice())
    .bind(fake_hash(0, 99).as_slice())
    .execute(&pool)
    .await
    .expect("seed event with controlled stored_at");

    let adapter = PgCurationDecisionsRepository::new(pool.clone());

    // Apply the cutoff: only the future event lands after.
    let rows = adapter
        .list_decisions(CurationDecisionFilter {
            since: Some(cutoff),
            ..CurationDecisionFilter::default()
        })
        .await
        .expect("list_decisions");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.event_id).collect();
    assert!(
        ids.contains(&future_event_id),
        "post-cutoff event must surface"
    );
    assert!(
        !ids.contains(&_old_event),
        "pre-cutoff event must NOT surface under --since filter"
    );

    cleanup_repo(&pool, repo).await;
}

// ---------------------------------------------------------------------------
// Test 5 — `--repository` filter narrows waive/block rows to the
// matching repo; exclude/unexclude rows are no-op and still surface.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_decisions_repository_filter_narrows_artifact_keyed_rows() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_a = seed_repo(&pool, "npm").await;
    let repo_b = seed_repo(&pool, "pypi").await;
    let policy = seed_policy(&pool).await;
    let curator = Uuid::new_v4();

    let art_a = seed_artifact(&pool, repo_a, "evil", "1.0").await;
    let art_b = seed_artifact(&pool, repo_b, "evil", "1.0").await;

    let waive_a =
        seed_curator_waive(&pool, art_a, curator, Uuid::new_v4(), "waive in repo A").await;
    let waive_b =
        seed_curator_waive(&pool, art_b, curator, Uuid::new_v4(), "waive in repo B").await;
    // Policy-keyed exclusion — repo filter must be a no-op for it.
    let exclusion_id = Uuid::new_v4();
    let exclude_evt = seed_exclusion_added(
        &pool,
        policy,
        exclusion_id,
        "CVE-2026-EX",
        "api",
        Some(curator),
        "policy exclusion",
        0,
    )
    .await;

    let adapter = PgCurationDecisionsRepository::new(pool.clone());
    let rows = adapter
        .list_decisions(CurationDecisionFilter {
            repository_id: Some(repo_a),
            ..CurationDecisionFilter::default()
        })
        .await
        .expect("list_decisions");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.event_id).collect();
    assert!(
        ids.contains(&waive_a),
        "repo A waive must surface under repo A filter"
    );
    assert!(
        !ids.contains(&waive_b),
        "repo B waive must NOT surface under repo A filter"
    );
    // Exclusion: policy-keyed → no-op for the repo filter (still surfaces).
    assert!(
        ids.contains(&exclude_evt),
        "policy-keyed exclusion must surface despite repo filter (scope is policy-keyed, not repo-keyed)"
    );

    cleanup_repo(&pool, repo_a).await;
    cleanup_repo(&pool, repo_b).await;
    cleanup_policy(&pool, policy).await;
}

// ---------------------------------------------------------------------------
// Test 6 — `--package` filter narrows artifact-keyed rows to the
// matching package name.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_decisions_package_filter_narrows_artifact_keyed_rows() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool, "npm").await;
    let curator = Uuid::new_v4();
    let art_evil = seed_artifact(&pool, repo, "evil-pkg", "1.0").await;
    let art_good = seed_artifact(&pool, repo, "good-pkg", "1.0").await;

    let waive_evil =
        seed_curator_waive(&pool, art_evil, curator, Uuid::new_v4(), "evil waive").await;
    let waive_good =
        seed_curator_waive(&pool, art_good, curator, Uuid::new_v4(), "good waive").await;

    let adapter = PgCurationDecisionsRepository::new(pool.clone());
    let rows = adapter
        .list_decisions(CurationDecisionFilter {
            package: Some("evil-pkg".into()),
            ..CurationDecisionFilter::default()
        })
        .await
        .expect("list_decisions");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.event_id).collect();
    assert!(ids.contains(&waive_evil));
    assert!(
        !ids.contains(&waive_good),
        "good-pkg waive must NOT surface under evil-pkg package filter"
    );

    cleanup_repo(&pool, repo).await;
}

// ---------------------------------------------------------------------------
// Test 7 — `--actor` filter narrows by envelope actor_id (works for
// all 4 event types).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_decisions_actor_filter_narrows_by_envelope_actor() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool, "npm").await;
    let curator_target = Uuid::new_v4();
    let curator_other = Uuid::new_v4();

    let art_target = seed_artifact(&pool, repo, "p", "1.0").await;
    let art_other = seed_artifact(&pool, repo, "p", "2.0").await;

    let target_waive =
        seed_curator_waive(&pool, art_target, curator_target, Uuid::new_v4(), "target").await;
    let other_waive =
        seed_curator_waive(&pool, art_other, curator_other, Uuid::new_v4(), "other").await;

    let adapter = PgCurationDecisionsRepository::new(pool.clone());
    let rows = adapter
        .list_decisions(CurationDecisionFilter {
            actor_id: Some(curator_target),
            ..CurationDecisionFilter::default()
        })
        .await
        .expect("list_decisions");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.event_id).collect();
    assert!(ids.contains(&target_waive));
    assert!(
        !ids.contains(&other_waive),
        "other curator's waive must NOT surface under --actor filter"
    );

    cleanup_repo(&pool, repo).await;
}

// ---------------------------------------------------------------------------
// Test 8 — `limit` clamps at 500 (adapter belt-and-braces).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_decisions_limit_clamps_at_500() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool, "npm").await;
    let curator = Uuid::new_v4();

    // 5 events — enough to verify the adapter doesn't choke and the
    // LIMIT clause clamps even when an oversize value is supplied.
    for i in 0..5 {
        let art = seed_artifact(&pool, repo, "p", &format!("1.{i}.0")).await;
        let _ = seed_curator_waive(&pool, art, curator, Uuid::new_v4(), "w").await;
    }

    let adapter = PgCurationDecisionsRepository::new(pool.clone());
    let rows = adapter
        .list_decisions(CurationDecisionFilter {
            limit: 9999,
            ..CurationDecisionFilter::default()
        })
        .await
        .expect("list_decisions");

    assert!(
        rows.len() <= 500,
        "limit must be clamped at 500; got {} rows",
        rows.len()
    );

    cleanup_repo(&pool, repo).await;
}
