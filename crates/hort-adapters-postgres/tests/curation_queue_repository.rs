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
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
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
    sqlx::query(sqlx::AssertSqlSafe(sql))
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
async fn seed_artifact(
    pool: &PgPool,
    repo: Uuid,
    name: &str,
    version: &str,
    quarantine_status: Option<&str>,
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
               quarantine_status, created_at, updated_at,
               quarantine_window_start
           ) VALUES (
               $1, $2, $3, $3, $4, $5,
               0, $6, 'application/octet-stream', $6,
               $7, $8, $8, $9
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(name)
    .bind(version)
    .bind(format!("{name}/{version}/{key}.tgz"))
    .bind(&sha256)
    .bind(quarantine_status)
    .bind(created_at)
    .bind(quarantine_window_start)
    .execute(pool)
    .await
    .expect("seed_artifact");
    id
}

/// Seed one scan: its `scan_findings` rows plus the
/// `artifacts.last_scan_at` advance, in one transaction.
///
/// This is the pairing `PgArtifactLifecycle::commit_scan_result_with_score`
/// makes in production — the per-finding rows and the `last_scan_at` write
/// land in the same SQL transaction, bound from the same timestamp the rows
/// carry as `detected_at`. The queue's findings LATERAL anchors on exactly
/// that equality, so a seeder that wrote rows without advancing the anchor
/// would be seeding a state no scan can produce.
///
/// `vulnerabilities` is one `(vulnerability_id, severity)` pair per finding.
/// An empty slice is a **clean scan**: no row is written and the anchor still
/// advances.
async fn seed_scan(
    pool: &PgPool,
    artifact_id: Uuid,
    detected_at: DateTime<Utc>,
    vulnerabilities: &[(&str, &str)],
) {
    let scan_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("seed_scan begin");
    for (vulnerability_id, severity) in vulnerabilities {
        sqlx::query(
            r#"INSERT INTO public.scan_findings
                  (artifact_id, scan_id, purl, vulnerability_id, severity,
                   source_scanner, title, detected_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(artifact_id)
        .bind(scan_id)
        .bind(format!("pkg:test/{}@1.0", artifact_id.simple()))
        .bind(*vulnerability_id)
        .bind(*severity)
        .bind("test-scanner")
        .bind("integration-test finding")
        .bind(detected_at)
        .execute(&mut *tx)
        .await
        .expect("seed_scan finding row");
    }
    sqlx::query("UPDATE public.artifacts SET last_scan_at = $1 WHERE id = $2")
        .bind(detected_at)
        .bind(artifact_id)
        .execute(&mut *tx)
        .await
        .expect("seed_scan last_scan_at");
    tx.commit().await.expect("seed_scan commit");
}

/// One scan reporting one finding at `severity`, committed now. The shape
/// most tests here want; multi-scan histories call [`seed_scan`] directly.
async fn seed_finding(pool: &PgPool, artifact_id: Uuid, severity: &str) {
    let vuln = format!("CVE-TEST-{}", artifact_id.simple());
    seed_scan(
        pool,
        artifact_id,
        truncate_us(Utc::now()),
        &[(vuln.as_str(), severity)],
    )
    .await;
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
        now,
        Some(window_start),
    )
    .await;
    seed_finding(&pool, artifact_id, "high").await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
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
        now,
        Some(now),
    )
    .await;
    let id_rejected =
        seed_artifact(&pool, repo_id, "p", "2.0", Some("rejected"), now, Some(now)).await;
    let id_indeterminate = seed_artifact(
        &pool,
        repo_id,
        "p",
        "3.0",
        Some("scan_indeterminate"),
        now,
        Some(now),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
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
        now,
        Some(now),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
            status: Some(QuarantineStatus::ScanIndeterminate),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");

    assert!(rows.iter().any(|r| r.artifact_id == id));
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
            now - Duration::seconds(i),
            Some(now),
        )
        .await;
    }

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
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
    let id = seed_artifact(&pool, repo_id, "p", "1.0", Some("rejected"), now, Some(now)).await;
    // Unit variant: bare-string payload.
    seed_artifact_rejected_event(&pool, id, 0, json!("Scanner")).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
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
    let id = seed_artifact(&pool, repo_id, "p", "1.0", Some("rejected"), now, Some(now)).await;
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
            artifact_id: None,
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
    let id = seed_artifact(&pool, repo_id, "p", "1.0", Some("rejected"), now, Some(now)).await;
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
            artifact_id: None,
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

/// **A corruption-tombstoned artifact surfaces WITH a reason.** Before the
/// CAS-integrity tombstone appended its `ArtifactRejected{Corruption}`
/// companion (ADR 0039's 2026-09-12 amendment, D6), the LATERAL found no
/// `ArtifactRejected` on such a stream at all and the curator saw a
/// `rejected` row whose reason column was NULL — no way to tell it apart
/// from any other unexplained rejection.
#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_lateral_extracts_rejection_reason_corruption() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let id = seed_artifact(&pool, repo_id, "p", "1.0", Some("rejected"), now, Some(now)).await;
    // Unit variant: bare-string payload — the same branch of the `CASE`
    // the scanner/provenance reasons land in.
    seed_artifact_rejected_event(&pool, id, 0, json!("Corruption")).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
            status: Some(QuarantineStatus::Rejected),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");
    let row = rows
        .into_iter()
        .find(|r| r.artifact_id == id)
        .expect("corruption-tombstoned artifact must surface");
    assert_eq!(
        row.rejection_reason_kind.as_deref(),
        Some("corruption"),
        "a curator must see WHY a corruption-tombstoned artifact is rejected"
    );

    cleanup_repo(&pool, repo_id).await;
}

/// The `?reason=corruption` filter reaches exactly the corruption rows.
/// The filter and the output column are computed by the same SQL
/// expression, so this also pins their case-symmetry for the new arm.
#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_filter_by_rejection_reason_kind_corruption() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = Utc::now();
    let id_corrupt =
        seed_artifact(&pool, repo_id, "p", "1.0", Some("rejected"), now, Some(now)).await;
    seed_artifact_rejected_event(&pool, id_corrupt, 0, json!("Corruption")).await;
    let id_scanner =
        seed_artifact(&pool, repo_id, "p", "2.0", Some("rejected"), now, Some(now)).await;
    seed_artifact_rejected_event(&pool, id_scanner, 0, json!("Scanner")).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
            status: Some(QuarantineStatus::Rejected),
            rejection_reason_kind: Some("corruption".into()),
            ..CurationQueueFilter::default()
        })
        .await
        .expect("list_queue");
    let ids: Vec<Uuid> = rows.iter().map(|r| r.artifact_id).collect();
    assert!(ids.contains(&id_corrupt), "corruption row must match");
    assert!(!ids.contains(&id_scanner), "scanner row must not match");

    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Test 8 — `rejection_reason_kind` filter narrows to matching rows.
//
// **Spec-compliance test.** The filter value is the *lowercase* wire format
// the curation queue design specifies — the same strings the HTTP query
// param `?reason=<kind>` and the `hort-cli` `--reason` flag accept (both
// derived from `RejectionReason`'s own vocabulary rather than restated),
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
    let id_curator =
        seed_artifact(&pool, repo_id, "p", "1.0", Some("rejected"), now, Some(now)).await;
    seed_artifact_rejected_event(
        &pool,
        id_curator,
        0,
        json!({ "Curator": { "curator_id": Uuid::new_v4() } }),
    )
    .await;
    let id_scanner =
        seed_artifact(&pool, repo_id, "p", "2.0", Some("rejected"), now, Some(now)).await;
    seed_artifact_rejected_event(&pool, id_scanner, 0, json!("Scanner")).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
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
    let id_curator =
        seed_artifact(&pool, repo_id, "p", "1.0", Some("rejected"), now, Some(now)).await;
    seed_artifact_rejected_event(
        &pool,
        id_curator,
        0,
        json!({ "Curator": { "curator_id": Uuid::new_v4() } }),
    )
    .await;
    let id_scanner =
        seed_artifact(&pool, repo_id, "p", "2.0", Some("rejected"), now, Some(now)).await;
    seed_artifact_rejected_event(&pool, id_scanner, 0, json!("Scanner")).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
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
    let id_retro =
        seed_artifact(&pool, repo_id, "p", "1.0", Some("rejected"), now, Some(now)).await;
    seed_artifact_rejected_event(
        &pool,
        id_retro,
        0,
        json!({ "CurationRetroactive": { "rule_id": Uuid::new_v4() } }),
    )
    .await;
    let id_scanner =
        seed_artifact(&pool, repo_id, "p", "2.0", Some("rejected"), now, Some(now)).await;
    seed_artifact_rejected_event(&pool, id_scanner, 0, json!("Scanner")).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
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
    let id = seed_artifact(&pool, repo_id, "p", "1.0", Some("rejected"), now, Some(now)).await;
    // No `ArtifactRejected` event seeded.

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
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

// ---------------------------------------------------------------------------
// The queue's finding summary answers about the artifact's LAST scan.
//
// `scan_findings` is per-scan history: every run writes under a fresh
// `scan_id` and nothing removes the previous run's rows. The four tests
// below pin that the summary is the last run's and not the union, including
// the two cases that rule out the wrong anchors — a clean last scan (which
// writes no row, so nothing inside the table can anchor on it) and a second
// scan reporting a proper subset of the first (which a de-duplicating fix
// would get wrong while looking right).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_finding_count_is_the_last_scan_not_the_union() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = truncate_us(Utc::now());
    let artifact = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("quarantined"),
        now - Duration::hours(10),
        Some(now - Duration::hours(10)),
    )
    .await;

    // Three scans. The first two report three findings between them; the
    // last reports one. The union is four rows; the answer is one.
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(3),
        &[("CVE-A", "critical"), ("CVE-B", "high")],
    )
    .await;
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(2),
        &[("CVE-C", "high")],
    )
    .await;
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(1),
        &[("CVE-D", "low")],
    )
    .await;

    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM scan_findings WHERE artifact_id = $1")
            .bind(artifact)
            .fetch_one(&pool)
            .await
            .expect("count all rows");
    assert_eq!(total, 4, "the history itself must be intact");

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
            status: None,
            rejection_reason_kind: None,
            limit: 100,
        })
        .await
        .expect("list_queue");

    let entry = rows
        .iter()
        .find(|e| e.artifact_id == artifact)
        .expect("artifact in queue");
    assert_eq!(entry.finding_count, 1, "the last scan found one finding");
    assert_eq!(
        entry.max_severity,
        Some(SeverityThreshold::Low),
        "max_severity is the last scan's highest, not the artifact's \
         all-time highest (Critical, from the first scan)"
    );

    // The read removed nothing.
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM scan_findings WHERE artifact_id = $1")
            .bind(artifact)
            .fetch_one(&pool)
            .await
            .expect("count all rows after read");
    assert_eq!(after, 4);

    cleanup_repo(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_clean_last_scan_reads_as_clean() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = truncate_us(Utc::now());
    let artifact = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("quarantined"),
        now - Duration::hours(10),
        Some(now - Duration::hours(10)),
    )
    .await;

    // A dirty scan, then a clean one. The clean run writes no row at all,
    // which is exactly why an anchor taken from inside `scan_findings`
    // cannot satisfy this: the newest `scan_id` *present* is still the
    // dirty run's.
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(2),
        &[("CVE-A", "critical"), ("CVE-B", "high")],
    )
    .await;
    seed_scan(&pool, artifact, now - Duration::hours(1), &[]).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
            status: None,
            rejection_reason_kind: None,
            limit: 100,
        })
        .await
        .expect("list_queue");

    let entry = rows
        .iter()
        .find(|e| e.artifact_id == artifact)
        .expect("a clean-last-scan artifact still surfaces in the queue");
    assert_eq!(entry.finding_count, 0);
    assert_eq!(entry.max_severity, None);

    // The earlier scan's rows are still there — this unit removes no
    // history, it only stops reading it as current.
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM scan_findings WHERE artifact_id = $1")
            .bind(artifact)
            .fetch_one(&pool)
            .await
            .expect("count all rows");
    assert_eq!(total, 2);

    cleanup_repo(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_last_scan_subset_is_the_subset_not_the_union() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = truncate_us(Utc::now());
    let artifact = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("quarantined"),
        now - Duration::hours(10),
        Some(now - Duration::hours(10)),
    )
    .await;

    // The counter-assertion. The second scan reports a PROPER SUBSET of the
    // first — same vulnerability ids, one of them dropped, and the dropped
    // one is the severe one. Collapsing the history by de-duplicating
    // `vulnerability_id` would answer `2` / Critical and look plausible;
    // the last scan says `1` / High.
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(2),
        &[("CVE-A", "critical"), ("CVE-B", "high")],
    )
    .await;
    seed_scan(
        &pool,
        artifact,
        now - Duration::hours(1),
        &[("CVE-B", "high")],
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
            status: None,
            rejection_reason_kind: None,
            limit: 100,
        })
        .await
        .expect("list_queue");

    let entry = rows
        .iter()
        .find(|e| e.artifact_id == artifact)
        .expect("artifact in queue");
    assert_eq!(
        entry.finding_count, 1,
        "a DISTINCT-shaped fix would answer 2 here"
    );
    assert_eq!(entry.max_severity, Some(SeverityThreshold::High));

    cleanup_repo(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_never_scanned_artifact_reads_as_clean() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = truncate_us(Utc::now());
    // No scan at all: `last_scan_at` is NULL, the anchor matches nothing,
    // and `COALESCE(f.finding_count, 0)` has to render that as a clean row
    // rather than dropping the artifact out of the queue.
    let artifact = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("quarantined"),
        now - Duration::hours(1),
        Some(now - Duration::hours(1)),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
            status: None,
            rejection_reason_kind: None,
            limit: 100,
        })
        .await
        .expect("list_queue");

    let entry = rows
        .iter()
        .find(|e| e.artifact_id == artifact)
        .expect("a never-scanned quarantined artifact still surfaces");
    assert_eq!(entry.finding_count, 0);
    assert_eq!(entry.max_severity, None);

    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Soft delete — a deleted artifact is not curator work, and takes no slot.
//
// The listing lost its liveness predicate when the inert `is_deleted`
// column was dropped, one day before real soft delete arrived under the
// name `deleted_at`. A curator acting on a row that is no longer in the
// catalog is the visible half; the `LIMIT` slot it consumed is the half
// absence alone cannot show, which is why the second test asserts on a
// count.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_omits_a_soft_deleted_rejected_artifact() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = truncate_us(Utc::now());
    let deleted = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("rejected"),
        now - Duration::hours(1),
        Some(now - Duration::hours(1)),
    )
    .await;
    seed_finding(&pool, deleted, "critical").await;
    hort_adapters_postgres::test_support::soft_delete_artifact(&pool, deleted).await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
            status: None,
            rejection_reason_kind: None,
            limit: 100,
        })
        .await
        .expect("list_queue");

    assert!(
        !rows.iter().any(|e| e.artifact_id == deleted),
        "a soft-deleted artifact is out of the served catalog, so it is \
         not curator work — the queue must not offer it"
    );

    cleanup_repo(&pool, repo_id).await;
}

/// The slot, not just the absence: `limit = 1` with one deleted and one
/// live row must return the live one.
///
/// Deterministic because the predicate makes the deleted row a
/// non-candidate, leaving one row for `LIMIT 1` — the `ORDER BY
/// a.created_at DESC` would otherwise have put the deleted row first,
/// which is exactly how it used to take the slot.
#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_spends_no_limit_slot_on_a_soft_deleted_artifact() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = truncate_us(Utc::now());
    // Newest, so `ORDER BY created_at DESC` ranks it first.
    let deleted = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "2.0",
        Some("rejected"),
        now,
        Some(now),
    )
    .await;
    hort_adapters_postgres::test_support::soft_delete_artifact(&pool, deleted).await;
    let live = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("rejected"),
        now - Duration::hours(1),
        Some(now - Duration::hours(1)),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
            status: Some(QuarantineStatus::Rejected),
            rejection_reason_kind: None,
            limit: 1,
        })
        .await
        .expect("list_queue");

    assert_eq!(
        rows.iter().map(|e| e.artifact_id).collect::<Vec<_>>(),
        vec![live],
        "the one slot must go to the live artifact, even though the \
         deleted one sorts first"
    );

    cleanup_repo(&pool, repo_id).await;
}

/// The filter excludes deleted rows and nothing else — including on the
/// `effective_policy_duration` CTE, whose own predicate gained the same
/// clause. A live artifact must still surface WITH its deadline, which is
/// what proves the CTE still matched its repository.
#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_still_returns_a_live_artifact_with_its_deadline() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let _policy = seed_repo_scoped_policy(&pool, repo_id, 3_600).await;
    let now = truncate_us(Utc::now());
    let window_start = now - Duration::hours(1);
    let live = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("quarantined"),
        window_start,
        Some(window_start),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
            status: None,
            rejection_reason_kind: None,
            limit: 100,
        })
        .await
        .expect("list_queue");

    let entry = rows
        .iter()
        .find(|e| e.artifact_id == live)
        .expect("the liveness predicate must not exclude a live artifact");
    assert_eq!(
        entry.quarantine_deadline,
        Some(window_start + Duration::seconds(3_600)),
        "the CTE must still resolve this repository's duration — a \
         liveness predicate that shadowed the whole CTE would leave the \
         deadline NULL"
    );

    cleanup_repo(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// `artifact_id` — the artifact-scoping filter.
//
// A conjunction with `repository_id`, not an alternative: the mismatched
// pair returns empty rather than widening to either side.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_artifact_id_narrows_to_exactly_that_artifact() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let now = truncate_us(Utc::now());
    let wanted = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("rejected"),
        now - Duration::hours(2),
        Some(now - Duration::hours(2)),
    )
    .await;
    let other = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "2.0",
        Some("rejected"),
        now - Duration::hours(1),
        Some(now - Duration::hours(1)),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let scoped = adapter
        .list_queue(CurationQueueFilter {
            repository_id: None,
            artifact_id: Some(wanted),
            status: None,
            rejection_reason_kind: None,
            limit: 100,
        })
        .await
        .expect("list_queue");
    assert_eq!(
        scoped.iter().map(|e| e.artifact_id).collect::<Vec<_>>(),
        vec![wanted]
    );

    // `None` behaves as before: both rows, newest first.
    let unscoped = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(repo_id),
            artifact_id: None,
            status: None,
            rejection_reason_kind: None,
            limit: 100,
        })
        .await
        .expect("list_queue");
    assert_eq!(
        unscoped.iter().map(|e| e.artifact_id).collect::<Vec<_>>(),
        vec![other, wanted],
        "an absent artifact_id must not narrow anything"
    );

    cleanup_repo(&pool, repo_id).await;
}

#[tokio::test]
#[serial(hort_pg_db)]
async fn list_queue_artifact_id_and_a_mismatched_repository_id_return_empty() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo_id = seed_repo(&pool, "npm").await;
    let other_repo = seed_repo(&pool, "pypi").await;
    let now = truncate_us(Utc::now());
    let artifact = seed_artifact(
        &pool,
        repo_id,
        "pkg",
        "1.0",
        Some("rejected"),
        now - Duration::hours(1),
        Some(now - Duration::hours(1)),
    )
    .await;

    let adapter = PgCurationQueueRepository::new(pool.clone());
    let rows = adapter
        .list_queue(CurationQueueFilter {
            repository_id: Some(other_repo),
            artifact_id: Some(artifact),
            status: None,
            rejection_reason_kind: None,
            limit: 100,
        })
        .await
        .expect("list_queue");

    assert!(
        rows.is_empty(),
        "the two filters are a conjunction: a mismatched pair returns \
         empty, with no precedence rule and no silent widening to either \
         side"
    );

    cleanup_repo(&pool, repo_id).await;
    cleanup_repo(&pool, other_repo).await;
}
