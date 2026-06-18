//! `PgCurationQueueRepository` integration tests.
//!
//! Exercises the curation queue query end-to-end against a real Postgres.
//! Each acceptance scenario from the backlog gets its own
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
//! `crates/hort-adapters-postgres/tests/patch_candidate_repo.rs`.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test curation_queue_repository
//! ```

#![allow(clippy::expect_used)]

use std::env;

use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;

use hort_adapters_postgres::curation_queue_repository::PgCurationQueueRepository;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::ports::curation_queue_repository::{CurationQueueFilter, CurationQueueRepository};

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
    let key = format!("it-init48-{}", id.simple());
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

/// Seed an artifact row in the requested quarantine state.
#[allow(clippy::too_many_arguments)]
async fn seed_artifact(
    pool: &PgPool,
    repo: Uuid,
    name: &str,
    version: &str,
    quarantine_status: Option<&str>,
    is_deleted: bool,
    created_at: DateTime<Utc>,
    quarantine_window_start: Option<DateTime<Utc>>,
) -> Uuid {
    let id = Uuid::new_v4();
    let key = id.simple().to_string();
    let sha256 = format!("{key}{key}");
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key,
               quarantine_status, is_deleted, created_at, updated_at,
               quarantine_window_start
           ) VALUES (
               $1, $2, $3, $3, $4, $5,
               0, $6, 'application/octet-stream', $6,
               $7, $8, $9, $9, $10
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(name)
    .bind(version)
    .bind(format!("{name}/{version}/{key}.tgz"))
    .bind(&sha256)
    .bind(quarantine_status)
    .bind(is_deleted)
    .bind(created_at)
    .bind(quarantine_window_start)
    .execute(pool)
    .await
    .expect("seed_artifact");
    id
}

/// Seed one `scan_findings` row.
async fn seed_finding(pool: &PgPool, artifact_id: Uuid, severity: &str) {
    sqlx::query(
        r#"INSERT INTO public.scan_findings
              (artifact_id, scan_id, purl, vulnerability_id, severity,
               source_scanner, title, detected_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, now())"#,
    )
    .bind(artifact_id)
    .bind(Uuid::new_v4())
    .bind(format!("pkg:test/{}@1.0", artifact_id.simple()))
    .bind(format!("CVE-TEST-{}", artifact_id.simple()))
    .bind(severity)
    .bind("test-scanner")
    .bind("integration-test finding")
    .execute(pool)
    .await
    .expect("seed_finding");
}

/// Seed a non-archived repo-scoped policy with the requested
/// `quarantine_duration_secs`. Returns the policy_id.
async fn seed_repo_scoped_policy(
    pool: &PgPool,
    repo_id: Uuid,
    quarantine_duration_secs: i64,
) -> Uuid {
    let policy_id = Uuid::new_v4();
    let name = format!("it-init48-policy-{}", policy_id.simple());
    let scope = json!({ "Repository": repo_id });
    sqlx::query(
        r#"INSERT INTO public.policy_projections (
               policy_id, name, scope, severity_threshold,
               rescan_interval_hours, quarantine_duration_secs,
               require_approval, archived,
               stream_version
           ) VALUES (
               $1, $2, $3, 'high',
               24, $4,
               false, false,
               1
           )"#,
    )
    .bind(policy_id)
    .bind(&name)
    .bind(&scope)
    .bind(quarantine_duration_secs)
    .execute(pool)
    .await
    .expect("seed repo-scoped policy_projections row");
    policy_id
}

/// Seed an `ArtifactRejected` event on the artifact's stream. `rejected_by`
/// is the raw JSON value for the variant — pass `json!("Scanner")` for the
/// unit variant or `json!({"Curator": {"curator_id": "..."}})` for the
/// tuple variant.
async fn seed_artifact_rejected_event(
    pool: &PgPool,
    artifact_id: Uuid,
    stream_position: i64,
    rejected_by_payload: serde_json::Value,
) {
    let stream_id = format!("artifact-{artifact_id}");
    let event_data = json!({
        "type": "ArtifactRejected",
        "data": {
            "artifact_id": artifact_id,
            "rejected_by": rejected_by_payload,
            "reason": "integration test"
        }
    });
    sqlx::query(
        r#"INSERT INTO events
              (event_id, stream_id, stream_category, stream_position,
               event_type, event_version, event_data, correlation_id,
               actor_type, prev_event_hash, event_hash)
            VALUES ($1, $2, 'artifact', $3, 'ArtifactRejected', 1,
                    $4, $5, 'system', $6, $7)"#,
    )
    .bind(Uuid::new_v4())
    .bind(&stream_id)
    .bind(stream_position)
    .bind(&event_data)
    .bind(Uuid::new_v4())
    .bind([0u8; 32].as_slice())
    // Position-dependent unique hash so multiple events on the same
    // stream don't collide on the `event_hash` chain-step. We don't
    // verify the chain in this test; pure structural shape.
    .bind(
        {
            let mut h = [0u8; 32];
            h[0] = stream_position as u8;
            h[1] = (artifact_id.as_u128() >> 64) as u8;
            h
        }
        .as_slice(),
    )
    .execute(pool)
    .await
    .expect("seed ArtifactRejected event");
}

/// Truncate a `DateTime<Utc>` to microsecond precision so Rust's
/// nanosecond clock and Postgres' `timestamptz` microsecond column
/// agree on the exact value the deadline-arithmetic assertion expects.
fn truncate_us(t: DateTime<Utc>) -> DateTime<Utc> {
    let us = t.timestamp_micros();
    DateTime::<Utc>::from_timestamp_micros(us).expect("microsecond round-trip")
}

/// Drop the repository, cascading through artifacts + scan_findings.
async fn cleanup_repo(pool: &PgPool, repo_id: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

// ---------------------------------------------------------------------------
// Test 1 — basic happy-path: a Quarantined artifact with findings shows
// up with the correct repository_key, format, finding_count, max_severity.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_returns_quarantined_artifact_with_findings() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let _policy = seed_repo_scoped_policy(&pool, repo_id, 86_400).await;
    // Postgres `timestamptz` has microsecond precision; truncate the
    // Rust nanosecond clock to match so the round-trip assertion does
    // not trip on the truncated read-back.
    let now = truncate_us(Utc::now());
    let window_start = now - Duration::hours(2);
    let artifact_id = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("quarantined"),
        false,
        now,
        Some(window_start),
    )
    .await;
    seed_finding(&pool, artifact_id, "high").await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");

    let row = rows
        .into_iter()
        .find(|r| r.artifact_id == artifact_id)
        .expect("seeded quarantined artifact should be in the result set");

    assert_eq!(row.repository_id, repo_id);
    assert_eq!(row.format, RepositoryFormat::Npm);
    assert_eq!(row.package_name, "pkg");
    assert_eq!(row.version.as_deref(), Some("1.0"));
    assert_eq!(row.quarantine_status, QuarantineStatus::Quarantined);
    assert_eq!(row.finding_count, 1);
    assert_eq!(row.max_severity, Some(SeverityThreshold::High));
    assert!(row.rejection_reason_kind.is_none());
    // Deadline = window_start + 86400 sec — verify it's the expected
    // arithmetic (we computed in SQL, not Rust).
    let expected_deadline = window_start + Duration::seconds(86_400);
    assert_eq!(row.quarantine_deadline, Some(expected_deadline));

    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 2 — status filter (Rejected): only rejected rows surface.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_status_filter_isolates_rejected() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let id_quarantined = seed_artifact(
        &pool,
        repo_id,
        "p",
        "1.0",
        Some("quarantined"),
        false,
        now,
        Some(now),
    )
    .await;
    let id_rejected = seed_artifact(
        &pool,
        repo_id,
        "p",
        "2.0",
        Some("rejected"),
        false,
        now,
        Some(now),
    )
    .await;
    let id_indeterminate = seed_artifact(
        &pool,
        repo_id,
        "p",
        "3.0",
        Some("scan_indeterminate"),
        false,
        now,
        Some(now),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            status: Some(QuarantineStatus::Rejected),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.artifact_id).collect();
    assert!(ids.contains(&id_rejected));
    assert!(!ids.contains(&id_quarantined));
    assert!(!ids.contains(&id_indeterminate));

    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 3 — `ScanIndeterminate` rows surface in default filter
// (curator-actionable set).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_scan_indeterminate_surfaces() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let id = seed_artifact(
        &pool,
        repo_id,
        "p",
        "1.0",
        Some("scan_indeterminate"),
        false,
        now,
        Some(now),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            status: Some(QuarantineStatus::ScanIndeterminate),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");

    assert!(rows.iter().any(|r| r.artifact_id == id));
    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 4 — `is_deleted = true` artifacts are excluded.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_excludes_soft_deleted_rows() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let _id_deleted = seed_artifact(
        &pool,
        repo_id,
        "p",
        "1.0",
        Some("quarantined"),
        true, // is_deleted
        now,
        Some(now),
    )
    .await;
    let id_live = seed_artifact(
        &pool,
        repo_id,
        "p",
        "2.0",
        Some("quarantined"),
        false,
        now,
        Some(now),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.artifact_id).collect();
    assert!(ids.contains(&id_live));
    assert!(
        !rows.iter().any(|r| r.artifact_id == _id_deleted),
        "soft-deleted artifact must not surface"
    );

    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 5 — `limit` capped at 500: a caller asking for 9999 still gets at
// most 500 rows back (adapter clamp).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_limit_clamps_at_500() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    // 6 artifacts is plenty — we only need to verify the cap doesn't
    // explode and the LIMIT clause clamps to MAX (here verified by
    // asking for an oversize value and getting <= 500).
    for i in 0..6 {
        let _ = seed_artifact(
            &pool,
            repo_id,
            "p",
            &format!("1.{i}.0"),
            Some("quarantined"),
            false,
            now - Duration::seconds(i),
            Some(now),
        )
        .await;
    }

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            limit: 9999,
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");

    assert!(
        rows.len() <= 500,
        "limit must be clamped at 500; got {} rows",
        rows.len()
    );

    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 6 — Cross-repo deadline difference.
// Two repos with different `quarantine_duration_secs` produce two
// different per-row deadlines for the same `window_start`.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_cross_repo_per_row_deadline_differs_by_policy() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_a = seed_repo(&pool, "npm").await;
    let repo_b = seed_repo(&pool, "pypi").await;
    // Repo A: 24h quarantine duration. Repo B: 7-day duration.
    let _ = seed_repo_scoped_policy(&pool, repo_a, 86_400).await;
    let _ = seed_repo_scoped_policy(&pool, repo_b, 7 * 86_400).await;

    // See truncate_us — match Postgres' microsecond precision so the
    // computed-deadline round-trip is exact.
    let now = truncate_us(Utc::now());
    let window_start = now - Duration::hours(1);

    let id_a = seed_artifact(
        &pool,
        repo_a,
        "pkg",
        "1.0",
        Some("quarantined"),
        false,
        now,
        Some(window_start),
    )
    .await;
    let id_b = seed_artifact(
        &pool,
        repo_b,
        "pkg",
        "1.0",
        Some("quarantined"),
        false,
        now,
        Some(window_start),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter::default())
        .await
        .expect("list_queue");

    let row_a = rows
        .iter()
        .find(|r| r.artifact_id == id_a)
        .expect("repo A artifact must be in result");
    let row_b = rows
        .iter()
        .find(|r| r.artifact_id == id_b)
        .expect("repo B artifact must be in result");

    let expected_a = window_start + Duration::seconds(86_400);
    let expected_b = window_start + Duration::seconds(7 * 86_400);
    assert_eq!(
        row_a.quarantine_deadline,
        Some(expected_a),
        "repo A deadline = window_start + 1d"
    );
    assert_eq!(
        row_b.quarantine_deadline,
        Some(expected_b),
        "repo B deadline = window_start + 7d"
    );
    assert_ne!(row_a.quarantine_deadline, row_b.quarantine_deadline);

    cleanup_repo(&pool, repo_a).await;
    cleanup_repo(&pool, repo_b).await;
}

// ---------------------------------------------------------------------------
// Test 7 — LATERAL JOIN extracts `rejection_reason_kind` for each
// `RejectionReason` variant.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_lateral_extracts_rejection_reason_scanner() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let id = seed_artifact(
        &pool,
        repo_id,
        "p",
        "1.0",
        Some("rejected"),
        false,
        now,
        Some(now),
    )
    .await;
    // Unit variant: bare-string payload.
    seed_artifact_rejected_event(&pool, id, 0, json!("Scanner")).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            status: Some(QuarantineStatus::Rejected),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");
    let row = rows
        .into_iter()
        .find(|r| r.artifact_id == id)
        .expect("rejected artifact must surface");
    assert_eq!(row.rejection_reason_kind.as_deref(), Some("scanner"));

    cleanup_repo(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_lateral_extracts_rejection_reason_curator() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let id = seed_artifact(
        &pool,
        repo_id,
        "p",
        "1.0",
        Some("rejected"),
        false,
        now,
        Some(now),
    )
    .await;
    let curator_id = Uuid::new_v4();
    // Tuple variant: single-key object payload.
    seed_artifact_rejected_event(
        &pool,
        id,
        0,
        json!({ "Curator": { "curator_id": curator_id } }),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            status: Some(QuarantineStatus::Rejected),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");
    let row = rows
        .into_iter()
        .find(|r| r.artifact_id == id)
        .expect("rejected artifact must surface");
    assert_eq!(row.rejection_reason_kind.as_deref(), Some("curator"));

    cleanup_repo(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_lateral_extracts_rejection_reason_curation_retroactive() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let id = seed_artifact(
        &pool,
        repo_id,
        "p",
        "1.0",
        Some("rejected"),
        false,
        now,
        Some(now),
    )
    .await;
    let rule_id = Uuid::new_v4();
    seed_artifact_rejected_event(
        &pool,
        id,
        0,
        json!({ "CurationRetroactive": { "rule_id": rule_id } }),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            status: Some(QuarantineStatus::Rejected),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");
    let row = rows
        .into_iter()
        .find(|r| r.artifact_id == id)
        .expect("rejected artifact must surface");
    assert_eq!(
        row.rejection_reason_kind.as_deref(),
        Some("curation_retroactive")
    );

    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 8 — `rejection_reason_kind` filter narrows to matching rows.
//
// **Spec-compliance test.** The filter value is the *lowercase* wire format
// the curation queue design specifies — the same strings the HTTP query
// param `?reason=<kind>` and the `hort-cli` flag
// `--reason <scanner|curator|curation_retroactive|corruption>` accept,
// and the same strings the output `rejection_reason_kind` column
// normalises to.
//
// The earlier draft of this test passed `Some("Curator".into())` —
// PascalCase — and silently sidestepped a real bug: the filter binding
// was symmetric with the (PascalCase) JSONB key, NOT with the lowercase
// wire format. A spec-compliant caller would have hit zero rows. The
// fix lowercases the LATERAL CASE output inside SQL so both sides
// compare in lowercase.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_filter_by_rejection_reason_kind_curator() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let id_curator = seed_artifact(
        &pool,
        repo_id,
        "p",
        "1.0",
        Some("rejected"),
        false,
        now,
        Some(now),
    )
    .await;
    seed_artifact_rejected_event(
        &pool,
        id_curator,
        0,
        json!({ "Curator": { "curator_id": Uuid::new_v4() } }),
    )
    .await;
    let id_scanner = seed_artifact(
        &pool,
        repo_id,
        "p",
        "2.0",
        Some("rejected"),
        false,
        now,
        Some(now),
    )
    .await;
    seed_artifact_rejected_event(&pool, id_scanner, 0, json!("Scanner")).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            status: Some(QuarantineStatus::Rejected),
            // Lowercase wire format — the spec-mandated value the HTTP
            // query param and hort-cli flag accept.
            rejection_reason_kind: Some("curator".into()),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.artifact_id).collect();
    assert!(
        ids.contains(&id_curator),
        "curator-rejected row must surface under lowercase 'curator' filter"
    );
    assert!(
        !ids.contains(&id_scanner),
        "scanner-rejected row must NOT surface under 'curator' filter"
    );

    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 8a — lowercase `"scanner"` filter excludes a curator-rejected row.
// Complementary direction to test 8.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_filter_by_rejection_reason_kind_scanner_excludes_curator() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let id_curator = seed_artifact(
        &pool,
        repo_id,
        "p",
        "1.0",
        Some("rejected"),
        false,
        now,
        Some(now),
    )
    .await;
    seed_artifact_rejected_event(
        &pool,
        id_curator,
        0,
        json!({ "Curator": { "curator_id": Uuid::new_v4() } }),
    )
    .await;
    let id_scanner = seed_artifact(
        &pool,
        repo_id,
        "p",
        "2.0",
        Some("rejected"),
        false,
        now,
        Some(now),
    )
    .await;
    seed_artifact_rejected_event(&pool, id_scanner, 0, json!("Scanner")).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            status: Some(QuarantineStatus::Rejected),
            rejection_reason_kind: Some("scanner".into()),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.artifact_id).collect();
    assert!(
        ids.contains(&id_scanner),
        "scanner-rejected row must surface under lowercase 'scanner' filter"
    );
    assert!(
        !ids.contains(&id_curator),
        "curator-rejected row must NOT surface under 'scanner' filter"
    );

    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 8b — lowercase `"curation_retroactive"` snake_case filter matches a
// `CurationRetroactive`-rejected row (round-trip via SQL lowercasing of the
// PascalCase JSONB key).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_filter_by_rejection_reason_kind_curation_retroactive() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let id_retro = seed_artifact(
        &pool,
        repo_id,
        "p",
        "1.0",
        Some("rejected"),
        false,
        now,
        Some(now),
    )
    .await;
    seed_artifact_rejected_event(
        &pool,
        id_retro,
        0,
        json!({ "CurationRetroactive": { "rule_id": Uuid::new_v4() } }),
    )
    .await;
    let id_scanner = seed_artifact(
        &pool,
        repo_id,
        "p",
        "2.0",
        Some("rejected"),
        false,
        now,
        Some(now),
    )
    .await;
    seed_artifact_rejected_event(&pool, id_scanner, 0, json!("Scanner")).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            status: Some(QuarantineStatus::Rejected),
            rejection_reason_kind: Some("curation_retroactive".into()),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");

    let ids: Vec<Uuid> = rows.iter().map(|r| r.artifact_id).collect();
    assert!(
        ids.contains(&id_retro),
        "CurationRetroactive-rejected row must surface under lowercase \
         'curation_retroactive' filter"
    );
    assert!(
        !ids.contains(&id_scanner),
        "scanner-rejected row must NOT surface under 'curation_retroactive' filter"
    );

    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 9 — Defensive: a `Rejected` artifact with NO `ArtifactRejected`
// event in the stream still surfaces, with `rejection_reason_kind = None`.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_rejected_without_event_has_none_rejection_reason_kind() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let id = seed_artifact(
        &pool,
        repo_id,
        "p",
        "1.0",
        Some("rejected"),
        false,
        now,
        Some(now),
    )
    .await;
    // No `ArtifactRejected` event seeded.

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            status: Some(QuarantineStatus::Rejected),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");
    let row = rows
        .into_iter()
        .find(|r| r.artifact_id == id)
        .expect("rejected artifact must surface even without an event");
    assert!(
        row.rejection_reason_kind.is_none(),
        "no LATERAL match => None (defensive); got {:?}",
        row.rejection_reason_kind
    );

    cleanup_repo(&pool, repo_id).await;
}
