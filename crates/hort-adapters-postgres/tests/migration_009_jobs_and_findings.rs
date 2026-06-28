//! `009_scan_jobs_and_findings.sql` migration tests.
//!
//! Asserts the schema invariants the migration ships with. The
//! `scan_jobs` → `jobs` table rename is folded directly into 009
//! (pre-release in-place edit per the `feedback_pre_release_migrations`
//! discipline); these tests pin that union shape.
//!
//! The migration is delivered as a single union from day 1 with:
//!
//! 1. `jobs` (the cross-kind dispatch table; the v1 kinds use
//!    **hyphen-separated literals**: `'scan'`, `'cron-rescan-tick'`,
//!    `'advisory-watch-tick'`, `'retention-evaluate'`,
//!    `'retention-purge'`, `'eventstore-archive'`, `'staging-sweep'`,
//!    `'noop'`. Underscore literals are bugs.).
//! 2. The partial unique on `(artifact_id) WHERE kind='scan' AND
//!    artifact_id IS NOT NULL` enforces "at most one scan job per
//!    artifact" without preventing arbitrary count of cross-kind rows
//!    (ADR 0028).
//! 3. `scan_findings` composite PK.
//! 4. `repo_security_scores` per-repo aggregate projection.
//! 5. `scanner_registry` worker liveness table.
//! 6. `artifacts.last_scan_at` denorm column + partial index
//!    (feeds the cron-rescan scheduler — see
//!    `docs/architecture/explanation/scanning-pipeline.md`).
//!
//! Tests follow the convention in `api_tokens_migration.rs`:
//! require `DATABASE_URL`; if unset, every test early-returns `Ok` so
//! dev environments without a database keep the suite green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test migration_009_jobs_and_findings
//! ```

#![allow(clippy::expect_used)]

use std::env;

use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Connect as the migration superuser; run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");
    Some(pool)
}

/// Seed a minimal repository row and return its id. Used by tests that
/// need to satisfy the `scan_findings.artifact_id` /
/// `repo_security_scores.repository_id` FK references introduced by
/// findings M3 + M4. Mirrors the `seed_repo` pattern from
/// `artifact_repo.rs` test fixtures so behaviour stays consistent
/// across the integration suite.
async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-mig009-{}", id.simple());
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $3,
               'pypi'::repository_format,
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
    .expect("seed repository row for migration 009 tests");
    id
}

/// Seed a minimal artifact row under `repo` and return its id. The
/// columns set here are the bare NOT-NULL minimum the
/// `artifacts` table demands; tests use the artifact id only as a
/// foreign-key target for `scan_findings.artifact_id`, so the
/// `checksum_sha256` value is a distinct-per-row hex blob rather
/// than a real SHA-256.
async fn seed_artifact(pool: &PgPool, repo: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let key = id.simple().to_string();
    // Build a 64-char hex blob from the UUID (32 hex chars) by
    // doubling the simple form. UNIQUE on (repository_id, path),
    // so the path uses the UUID to guarantee no collision.
    let sha256 = format!("{key}{key}");
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key
           ) VALUES (
               $1, $2, 'mig009', 'mig009', '0.0.0', $3,
               0, $4, 'application/octet-stream', $4
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(format!("simple/mig009/{key}.tar.gz"))
    .bind(&sha256)
    .execute(pool)
    .await
    .expect("seed artifact row for migration 009 tests");
    id
}

// ---------------------------------------------------------------------------
// Test 1 — `jobs` table accepts every v1 kind; partial unique enforces
// at-most-one scan job per artifact.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_009_creates_jobs_table_with_all_kinds() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    // Sanity — table exists.
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
                        WHERE table_schema = 'public' AND table_name = 'jobs')",
    )
    .fetch_one(&pool)
    .await
    .expect("probe jobs existence");
    assert!(
        table_exists,
        "jobs table must exist after running through 009"
    );

    // Insert one row per v1 kind. Every kind must succeed under
    // `status='pending'`. Hyphen-separated literals are the spec. The full
    // allow-list is defined inline in 009's `jobs.kind` CHECK; pre-1.0 a
    // new kind is added to that IN-list in place (ADR 0022). This test is
    // the SQL-CHECK side of the `VALID_TASK_KINDS` lock-step; the use-case
    // side is `crates/hort-server/tests/task_use_case_enqueue_real_db.rs`
    // (which walks `VALID_TASK_KINDS` directly through the real use case →
    // adapter → DB path). The in-place-edited 009 file IS the source of
    // truth and this fixture follows it.
    let all_kinds = [
        "scan",
        "cron-rescan-tick",
        "advisory-watch-tick",
        "retention-evaluate",
        "retention-purge",
        "eventstore-archive",
        "staging-sweep",
        "noop",
        "service-account-rotation",
        "eventstore-checkpoint",
        "replay-seen-prune",
        "quarantine-release-sweep",
        // Operator-supplied dependency-set bulk import.
        "seed-import",
        // Scheduled prefetch tick.
        "prefetch-tick",
        // Transitive prefetch cascade (per-version ingest unit).
        "prefetch",
        // Transitive prefetch cascade (driver).
        "prefetch-dependencies",
        // Terminal `prefetch%` row retention sweep.
        "prefetch-row-retention-sweep",
        // PEP 658 wheel-metadata backfill.
        "wheel-metadata-backfill",
        // Sigstore/cosign provenance verification.
        "provenance-verify",
        // `verify-event-chain` run liveness breadcrumb written by the
        // verify CLI's `record_run_completion`. NOT a worker-dispatched
        // task kind, so it is intentionally absent from `VALID_TASK_KINDS`
        // (this is a DB-CHECK-only kind, not part of the admin-task-invoke
        // lock-step).
        "verify-event-chain",
        // Async scan-policy re-evaluation pass (ADR 0041 Item 3); part of
        // the jobs.kind CHECK in 009. The dedicated real-adapter-path
        // DB-gated proof is `jobs_kind_check_policy_reevaluation.rs`.
        "policy-reevaluation",
    ];
    for kind in all_kinds {
        // Use a unique fresh artifact_id only for `kind='scan'`; the
        // other kinds set artifact_id NULL since the partial unique index
        // only constrains `kind='scan' AND artifact_id IS NOT NULL`.
        let artifact_id_param: Option<Uuid> = if kind == "scan" {
            Some(Uuid::new_v4())
        } else {
            None
        };
        sqlx::query("INSERT INTO public.jobs (kind, artifact_id) VALUES ($1, $2)")
            .bind(kind)
            .bind(artifact_id_param)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("INSERT kind={kind} must succeed: {e}"));
    }

    // Reject an unknown kind via CHECK.
    let bad = sqlx::query("INSERT INTO public.jobs (kind) VALUES ('not-a-kind')")
        .execute(&pool)
        .await
        .expect_err("unknown kind must be rejected by CHECK");
    let code = bad
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        code, "23514",
        "expected SQLSTATE 23514 (check_violation) for unknown kind, got {code}: {bad}"
    );

    // Partial unique on (artifact_id) WHERE kind='scan' AND artifact_id IS NOT NULL.
    // First scan-row with this artifact succeeds; the duplicate must fail.
    let dup_artifact = Uuid::new_v4();
    sqlx::query("INSERT INTO public.jobs (kind, artifact_id) VALUES ('scan', $1)")
        .bind(dup_artifact)
        .execute(&pool)
        .await
        .expect("first scan job for artifact succeeds");
    let dup_err = sqlx::query("INSERT INTO public.jobs (kind, artifact_id) VALUES ('scan', $1)")
        .bind(dup_artifact)
        .execute(&pool)
        .await
        .expect_err("duplicate scan job for same artifact must violate the partial unique");
    let dup_code = dup_err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        dup_code, "23505",
        "expected SQLSTATE 23505 (unique_violation), got {dup_code}: {dup_err}"
    );

    // Two `kind='noop'` rows with the same — actually NULL — `artifact_id` MUST
    // be permitted, since the partial unique excludes `artifact_id IS NULL`.
    sqlx::query("INSERT INTO public.jobs (kind) VALUES ('noop')")
        .execute(&pool)
        .await
        .expect("first noop job succeeds");
    sqlx::query("INSERT INTO public.jobs (kind) VALUES ('noop')")
        .execute(&pool)
        .await
        .expect("second noop job succeeds — partial unique must not apply");

    // Confirm both indexes exist.
    let mut index_rows = sqlx::query(
        "SELECT indexname FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'jobs' \
         ORDER BY indexname",
    )
    .fetch_all(&pool)
    .await
    .expect("probe jobs indexes");
    let indexes: Vec<String> = index_rows
        .iter_mut()
        .map(|r| r.get::<String, _>("indexname"))
        .collect();
    for required in ["jobs_scan_unique", "jobs_claim_idx"] {
        assert!(
            indexes.iter().any(|i| i == required),
            "expected index {required} to exist; saw {indexes:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2 — `scan_findings` composite PK enforces uniqueness.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_009_creates_scan_findings_pk_uniqueness() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    // M4 (FK on artifact_id) means we must seed a real artifacts row
    // before inserting findings. Pre-M4 the test passed a free-floating
    // UUID; now the FK rejects it.
    let repo_id = seed_repo(&pool).await;
    let artifact_id = seed_artifact(&pool, repo_id).await;
    let scan_id = Uuid::new_v4();
    let purl = "pkg:npm/foo@1.2.3";
    let cve = "CVE-2024-12345";
    let scanner = "trivy";

    // First insert succeeds.
    sqlx::query(
        "INSERT INTO public.scan_findings \
            (artifact_id, scan_id, purl, vulnerability_id, severity, cvss_score, \
             source_scanner, title, detected_at) \
         VALUES ($1, $2, $3, $4, 'high', 7.5, $5, 'Test finding', now())",
    )
    .bind(artifact_id)
    .bind(scan_id)
    .bind(purl)
    .bind(cve)
    .bind(scanner)
    .execute(&pool)
    .await
    .expect("first scan_findings insert succeeds");

    // Duplicate of the composite PK must fail.
    let dup = sqlx::query(
        "INSERT INTO public.scan_findings \
            (artifact_id, scan_id, purl, vulnerability_id, severity, cvss_score, \
             source_scanner, title, detected_at) \
         VALUES ($1, $2, $3, $4, 'high', 7.5, $5, 'Test finding', now())",
    )
    .bind(artifact_id)
    .bind(scan_id)
    .bind(purl)
    .bind(cve)
    .bind(scanner)
    .execute(&pool)
    .await
    .expect_err("duplicate composite PK must violate scan_findings PK");
    let code = dup
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        code, "23505",
        "expected SQLSTATE 23505 (unique_violation), got {code}: {dup}"
    );

    // Severity CHECK rejects an unknown level.
    let sev_err = sqlx::query(
        "INSERT INTO public.scan_findings \
            (artifact_id, scan_id, purl, vulnerability_id, severity, \
             source_scanner, title, detected_at) \
         VALUES ($1, $2, $3, 'CVE-DIFFERENT', 'BOGUS', $4, 'Test', now())",
    )
    .bind(artifact_id)
    .bind(scan_id)
    .bind(purl)
    .bind(scanner)
    .execute(&pool)
    .await
    .expect_err("unknown severity must be rejected by CHECK");
    let sev_code = sev_err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        sev_code, "23514",
        "expected SQLSTATE 23514 for unknown severity, got {sev_code}: {sev_err}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — `repo_security_scores` row defaults.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_009_creates_repo_security_scores() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    // M3 (FK on repository_id) means the row needs a real repositories
    // parent before insert; M2 (`updated_at DEFAULT now()`) means the
    // INSERT can omit `updated_at` entirely. Both are exercised here.
    let repo_id = seed_repo(&pool).await;
    sqlx::query(
        "INSERT INTO public.repo_security_scores (repository_id) \
         VALUES ($1)",
    )
    .bind(repo_id)
    .execute(&pool)
    .await
    .expect("insert repo_security_scores row (omitting updated_at — M2 default)");

    let row = sqlx::query(
        "SELECT quarantined_count, rejected_count, released_count, \
                critical_count, high_count, medium_count, low_count, \
                last_scan_at, updated_at \
         FROM public.repo_security_scores WHERE repository_id = $1",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("read back repo_security_scores row");

    assert_eq!(row.get::<i32, _>("quarantined_count"), 0);
    assert_eq!(row.get::<i32, _>("rejected_count"), 0);
    assert_eq!(row.get::<i32, _>("released_count"), 0);
    assert_eq!(row.get::<i32, _>("critical_count"), 0);
    assert_eq!(row.get::<i32, _>("high_count"), 0);
    assert_eq!(row.get::<i32, _>("medium_count"), 0);
    assert_eq!(row.get::<i32, _>("low_count"), 0);
    let last_scan_at: Option<chrono::DateTime<chrono::Utc>> = row.get("last_scan_at");
    assert!(
        last_scan_at.is_none(),
        "fresh row must have NULL last_scan_at; got {last_scan_at:?}"
    );
    // M2 — `updated_at DEFAULT now()` populates the column on INSERTs
    // that omit it. The column is NOT NULL so a missing default would
    // have failed the INSERT above; reading it back here pins the
    // semantic that "omit-on-insert" works as designed.
    let updated_at: chrono::DateTime<chrono::Utc> = row.get("updated_at");
    let now = chrono::Utc::now();
    assert!(
        (now - updated_at).num_seconds().abs() < 60,
        "updated_at must be set by DEFAULT now() within ~60s of the insert; \
         got updated_at={updated_at:?} now={now:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — `scanner_registry` round-trips a TEXT[] of backends.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_009_creates_scanner_registry() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let worker_id = format!("scanner-{}", Uuid::new_v4().simple());
    let backends = vec!["trivy".to_string(), "osv".to_string()];

    sqlx::query(
        "INSERT INTO public.scanner_registry \
            (worker_id, backends, registered_at, last_heartbeat) \
         VALUES ($1, $2, now(), now())",
    )
    .bind(&worker_id)
    .bind(&backends)
    .execute(&pool)
    .await
    .expect("insert scanner_registry row");

    let row = sqlx::query("SELECT backends FROM public.scanner_registry WHERE worker_id = $1")
        .bind(&worker_id)
        .fetch_one(&pool)
        .await
        .expect("read back scanner_registry row");

    let read_back: Vec<String> = row.get("backends");
    assert_eq!(
        read_back, backends,
        "TEXT[] backends must round-trip unchanged"
    );
}

// ---------------------------------------------------------------------------
// Test 5 — `artifacts.last_scan_at` exists with the partial index.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_009_artifacts_last_scan_at_column_exists_and_index_is_partial() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    // Column exists + correct type.
    let data_type: String = sqlx::query_scalar(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'artifacts' \
           AND column_name = 'last_scan_at'",
    )
    .fetch_one(&pool)
    .await
    .expect("probe artifacts.last_scan_at column type");
    assert_eq!(
        data_type, "timestamp with time zone",
        "last_scan_at must be TIMESTAMPTZ; got {data_type}"
    );

    // Column is nullable (existing rows take NULL).
    let is_nullable: String = sqlx::query_scalar(
        "SELECT is_nullable FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'artifacts' \
           AND column_name = 'last_scan_at'",
    )
    .fetch_one(&pool)
    .await
    .expect("probe artifacts.last_scan_at nullable");
    assert_eq!(
        is_nullable, "YES",
        "last_scan_at must be NULL-able; got {is_nullable}"
    );

    // Index exists with the expected partial WHERE clause.
    let indexdef: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'artifacts' \
           AND indexname = 'artifacts_last_scan_at_idx'",
    )
    .fetch_one(&pool)
    .await
    .expect("probe artifacts_last_scan_at_idx definition");

    assert!(
        indexdef.contains("last_scan_at"),
        "partial index must reference last_scan_at; got: {indexdef}"
    );
    assert!(
        indexdef.contains("quarantine_status") && indexdef.contains("released"),
        "partial index must include WHERE quarantine_status='released'; got: {indexdef}"
    );
}

// ---------------------------------------------------------------------------
// Test 6 — finding M4: `scan_findings.artifact_id` cascades on
// `artifacts` delete; finding M3: `repo_security_scores.repository_id`
// cascades on `repositories` delete.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_009_scan_findings_cascades_on_artifact_delete() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let repo_id = seed_repo(&pool).await;
    let artifact_id = seed_artifact(&pool, repo_id).await;

    // Insert a finding hanging off the artifact.
    sqlx::query(
        "INSERT INTO public.scan_findings \
            (artifact_id, scan_id, purl, vulnerability_id, severity, cvss_score, \
             source_scanner, title, detected_at) \
         VALUES ($1, $2, 'pkg:npm/cascade@1.0.0', 'CVE-CASCADE-1', \
                 'medium', 5.0, 'trivy', 'Cascade test', now())",
    )
    .bind(artifact_id)
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("seed finding for cascade test");

    // Sanity — finding row visible.
    let count_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.scan_findings WHERE artifact_id = $1")
            .bind(artifact_id)
            .fetch_one(&pool)
            .await
            .expect("count findings before delete");
    assert_eq!(
        count_before, 1,
        "fixture must show one finding before delete"
    );

    // Delete the artifact. ON DELETE CASCADE on the FK should drop the
    // finding row in the same statement.
    sqlx::query("DELETE FROM public.artifacts WHERE id = $1")
        .bind(artifact_id)
        .execute(&pool)
        .await
        .expect("delete artifact");

    let count_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.scan_findings WHERE artifact_id = $1")
            .bind(artifact_id)
            .fetch_one(&pool)
            .await
            .expect("count findings after artifact delete");
    assert_eq!(
        count_after, 0,
        "M4: finding must cascade-delete with its parent artifact; got {count_after} rows"
    );

    // Cleanup.
    let _ = sqlx::query("DELETE FROM public.repositories WHERE id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn migration_009_repo_security_scores_cascades_on_repository_delete() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let repo_id = seed_repo(&pool).await;

    // Insert score row (omit `updated_at` to also exercise the M2
    // default).
    sqlx::query("INSERT INTO public.repo_security_scores (repository_id) VALUES ($1)")
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("seed repo_security_scores row for cascade test");

    let count_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.repo_security_scores WHERE repository_id = $1",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("count score rows before delete");
    assert_eq!(count_before, 1, "fixture must show one score before delete");

    // Delete the repository — score row must follow via CASCADE.
    sqlx::query("DELETE FROM public.repositories WHERE id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("delete repository");

    let count_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.repo_security_scores WHERE repository_id = $1",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("count score rows after delete");
    assert_eq!(
        count_after, 0,
        "M3: score row must cascade-delete with its parent repository; got {count_after}"
    );
}

// ---------------------------------------------------------------------------
// Test 7 — finding H9: length CHECKs reject oversized text columns.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_009_scan_findings_rejects_oversized_text_columns() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let repo_id = seed_repo(&pool).await;
    let artifact_id = seed_artifact(&pool, repo_id).await;
    let scan_id = Uuid::new_v4();

    // 600-byte purl exceeds the 512 cap.
    let big_purl = "x".repeat(600);
    let purl_err = sqlx::query(
        "INSERT INTO public.scan_findings \
            (artifact_id, scan_id, purl, vulnerability_id, severity, \
             source_scanner, title, detected_at) \
         VALUES ($1, $2, $3, 'CVE-2024-LEN', 'low', 'trivy', 't', now())",
    )
    .bind(artifact_id)
    .bind(scan_id)
    .bind(&big_purl)
    .execute(&pool)
    .await
    .expect_err("600-byte purl must violate scan_findings_purl_length CHECK");
    let purl_code = purl_err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        purl_code, "23514",
        "expected SQLSTATE 23514 for oversize purl, got {purl_code}: {purl_err}"
    );

    // 200-byte vulnerability_id exceeds the 128 cap.
    let big_cve = "Y".repeat(200);
    let cve_err = sqlx::query(
        "INSERT INTO public.scan_findings \
            (artifact_id, scan_id, purl, vulnerability_id, severity, \
             source_scanner, title, detected_at) \
         VALUES ($1, $2, 'pkg:npm/x@1', $3, 'low', 'trivy', 't', now())",
    )
    .bind(artifact_id)
    .bind(scan_id)
    .bind(&big_cve)
    .execute(&pool)
    .await
    .expect_err("200-byte vulnerability_id must violate length CHECK");
    let cve_code = cve_err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(cve_code, "23514", "vulnerability_id length CHECK code");

    // 1500-byte title exceeds the 1024 cap.
    let big_title = "T".repeat(1500);
    let title_err = sqlx::query(
        "INSERT INTO public.scan_findings \
            (artifact_id, scan_id, purl, vulnerability_id, severity, \
             source_scanner, title, detected_at) \
         VALUES ($1, $2, 'pkg:npm/x@2', 'CVE-2024-T', 'low', 'trivy', $3, now())",
    )
    .bind(artifact_id)
    .bind(scan_id)
    .bind(&big_title)
    .execute(&pool)
    .await
    .expect_err("1500-byte title must violate length CHECK");
    let title_code = title_err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(title_code, "23514", "title length CHECK code");

    // 100-byte source_scanner exceeds the 64 cap.
    let big_scanner = "S".repeat(100);
    let scanner_err = sqlx::query(
        "INSERT INTO public.scan_findings \
            (artifact_id, scan_id, purl, vulnerability_id, severity, \
             source_scanner, title, detected_at) \
         VALUES ($1, $2, 'pkg:npm/x@3', 'CVE-2024-S', 'low', $3, 't', now())",
    )
    .bind(artifact_id)
    .bind(scan_id)
    .bind(&big_scanner)
    .execute(&pool)
    .await
    .expect_err("100-byte source_scanner must violate length CHECK");
    let scanner_code = scanner_err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(scanner_code, "23514", "source_scanner length CHECK code");
}

// ---------------------------------------------------------------------------
// Test 8 — finding M1: `'negligible'` severity is rejected by the CHECK.
// The domain `SeverityThreshold` enum has no `Negligible` variant; the
// Trivy adapter explicitly folds incoming `NEGLIGIBLE` to `Low`. The
// CHECK enforces that no v2 code path can ever land `'negligible'` in
// the column.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_009_scan_findings_rejects_negligible_severity() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let repo_id = seed_repo(&pool).await;
    let artifact_id = seed_artifact(&pool, repo_id).await;
    let scan_id = Uuid::new_v4();

    let err = sqlx::query(
        "INSERT INTO public.scan_findings \
            (artifact_id, scan_id, purl, vulnerability_id, severity, \
             source_scanner, title, detected_at) \
         VALUES ($1, $2, 'pkg:npm/foo@1.2.3', 'CVE-2024-NEG', \
                 'negligible', 'trivy', 'Test', now())",
    )
    .bind(artifact_id)
    .bind(scan_id)
    .execute(&pool)
    .await
    .expect_err("M1: 'negligible' must violate scan_findings_severity_check");
    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        code, "23514",
        "expected SQLSTATE 23514 (check_violation) for severity='negligible', \
         got {code}: {err}"
    );

    // Sibling assertion — the four canonical severities must still be
    // accepted, so the CHECK isn't accidentally too strict.
    for sev in ["critical", "high", "medium", "low"] {
        sqlx::query(
            "INSERT INTO public.scan_findings \
                (artifact_id, scan_id, purl, vulnerability_id, severity, \
                 source_scanner, title, detected_at) \
             VALUES ($1, $2, $3, $4, $5, 'trivy', 'Test', now())",
        )
        .bind(artifact_id)
        .bind(scan_id)
        .bind(format!("pkg:npm/foo@{sev}"))
        .bind(format!("CVE-2024-{sev}"))
        .bind(sev)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("severity '{sev}' must be accepted: {e}"));
    }
}

// ---------------------------------------------------------------------------
// Test 9 — finding L7: `scanner_registry.backends` rejects empty array.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_009_scanner_registry_rejects_empty_backends() {
    let Some(pool) = admin_pool().await else {
        return;
    };

    let worker_id = format!("scanner-empty-{}", Uuid::new_v4().simple());
    let empty: Vec<String> = Vec::new();

    let err = sqlx::query(
        "INSERT INTO public.scanner_registry \
            (worker_id, backends, registered_at, last_heartbeat) \
         VALUES ($1, $2, now(), now())",
    )
    .bind(&worker_id)
    .bind(&empty)
    .execute(&pool)
    .await
    .expect_err("L7: empty backends array must violate scanner_registry_backends_nonempty");
    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        code, "23514",
        "expected SQLSTATE 23514 for empty backends, got {code}: {err}"
    );
}
