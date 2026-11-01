//! The `jobs` row a scan execution leaves behind, against a real
//! PostgreSQL instance.
//!
//! ## The gap under test
//!
//! A `kind='scan'` row's result state used to be written twice per
//! execution by two owners. `ScanOrchestrationUseCase::record_outcome`
//! chose `mark_completed` / `mark_failed` / `reschedule` per outcome, and
//! `ScanTaskHandler::run` then returned a blanket
//! `TaskOutcome::Completed`, so `TaskDispatcher` wrote the same row again.
//! The second write won: the result-write fence is `AND attempts = $2` and
//! deliberately not the status, and `reschedule` leaves `attempts` alone,
//! so a `mark_completed` carrying the same attempt passed the fence and
//! turned a scheduled retry into `status='completed'`.
//!
//! Reported from a live instance: artifacts whose scan row read
//! `status=completed, attempts=1` with a transient compose failure still in
//! `last_error`, no `ScanCompleted`, no verdict, `last_scan_at` NULL — and
//! a release sweep that correctly declined them forever, because the job
//! row is the system's only record that an artifact is still owed a
//! verdict.
//!
//! The dispatcher is now the row's only writer and the scan path reports a
//! `ScanRowDisposition` instead. These tests assert what that produces **on
//! a real row**: the per-disposition row state, the attempt accounting
//! across two claims, and — for a persistence failure at the attempt cap —
//! that the artifact is left where a rescan sweep still sees it.
//!
//! ## Why the handler here is a stub
//!
//! A real `ScanTaskHandler` needs a whole `ScanOrchestrationUseCase`
//! (storage, scanners, advisories, format handlers). What these tests are
//! about is the *row*, so they drive the real `TaskDispatcher` and the real
//! `PgJobsRepository` with a handler that returns exactly the
//! `TaskOutcome`s `ScanTaskHandler::outcome_for` produces — one per
//! `ScanRowDisposition`, plus the undischarged-obligation case. The mapping
//! from `ScanRunOutcome` to disposition is pinned in `hort-app`'s own unit
//! tests, where the scan can be driven without a database.
//!
//! `DATABASE_URL`-gated per the project convention: when unset every test
//! early-returns. Every test that acquires a connection carries
//! `#[serial(hort_pg_db)]` — the migration set's `CREATE ROLE` and the
//! stale-database sweeper are cluster-global, so a per-test database is not
//! isolation from a concurrently-running sibling.
//!
//! ```bash
//! DATABASE_URL=postgresql://… \
//!   cargo test -p hort-adapters-postgres --test scan_row_single_owner
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;
use sqlx::{PgPool, Row};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use hort_adapters_postgres::event_store::PgEventStore;
use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_adapters_postgres::permission_grant_repo::PgPermissionGrantRepository;
use hort_adapters_postgres::rescan_candidates::PgRescanCandidatesRepository;
use hort_adapters_postgres::user_repo::PgUserRepository;
use hort_app::destructive_task_reauthorization::DestructiveTaskReauthorizer;
use hort_app::task_dispatcher::TaskDispatcher;
use hort_domain::error::DomainResult;
use hort_domain::ports::jobs_repository::{JobsRepository, REQUEUE_ON_LEASE_EXPIRY_KINDS};
use hort_domain::ports::rescan_candidates::RescanCandidatesRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;
use hort_domain::types::ContentHash;

/// The attempt budget these tests build the dispatcher with —
/// `HORT_SCANNER_MAX_ATTEMPTS`'s default, and the same number a real
/// worker also gives `ScanOrchestrationConfig::max_attempts`.
const ATTEMPT_CAP: u32 = 5;

/// `attempts` to seed so the *next* claim lands exactly on
/// [`ATTEMPT_CAP`]. The claim statement increments the column, so a row
/// seeded one below the cap is the execution at the budget's edge.
const AT_CAP_SEED: i32 = 4;
const _: () = assert!(AT_CAP_SEED >= 0 && AT_CAP_SEED as u32 + 1 == ATTEMPT_CAP);

/// Lease long enough that nothing lapses on its own.
const LEASE: Duration = Duration::from_secs(900);

/// The operator-visible text the reported incident carried. Used verbatim
/// so the assertions read as the row an operator would see.
const COMPOSE_ERROR: &str = "scanner compose failed: trivy: connection refused";

/// Fresh per-test database, fully migrated. `None` when `DATABASE_URL`
/// is unset — the single `?`-shaped skip `db_gate_not_silent` permits.
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

fn test_hash() -> ContentHash {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .expect("static valid SHA-256 hex")
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

async fn seed_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("it-scan-owner-{}", id.simple());
    sqlx::query(
        r#"INSERT INTO public.repositories (
               id, key, name, format, repo_type, storage_backend, storage_path,
               replication_priority
           ) VALUES (
               $1, $2, $3,
               'npm'::repository_format,
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
    .expect("seed repository row");
    id
}

/// Seed an artifact with the requested `quarantine_status` (SQL NULL for
/// `None` — the permissive default) and `last_scan_at` NULL, which is the
/// state of an artifact no scan ever completed.
async fn seed_artifact(pool: &PgPool, repo: Uuid, quarantine_status: Option<&str>) -> Uuid {
    let id = Uuid::new_v4();
    let key = id.simple().to_string();
    let sha256 = format!("{key}{key}");
    sqlx::query(
        r#"INSERT INTO public.artifacts (
               id, repository_id, name, name_as_published, version, path,
               size_bytes, checksum_sha256, content_type, storage_key,
               quarantine_status, last_scan_at
           ) VALUES (
               $1, $2, 'owned-row', 'owned-row', '0.0.0', $3,
               0, $4, 'application/octet-stream', $4,
               $5, NULL
           )"#,
    )
    .bind(id)
    .bind(repo)
    .bind(format!("owned-row/{key}.tgz"))
    .bind(&sha256)
    .bind(quarantine_status)
    .execute(pool)
    .await
    .expect("seed artifact row");
    id
}

/// Seed a claimable `kind='scan'` row at `attempts`, and return its id.
///
/// `attempts` is seeded directly because the claim increments it: a row
/// seeded at `cap - 1` is claimed *at* the cap, which is the boundary these
/// tests are about.
async fn seed_pending_scan(pool: &PgPool, artifact: Uuid, repo: Uuid, attempts: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO public.jobs \
            (kind, artifact_id, repository_id, content_hash, format, priority, status, attempts) \
         VALUES ('scan', $1, $2, $3, 'npm', 0, 'pending', $4) \
         RETURNING id",
    )
    .bind(artifact)
    .bind(repo)
    .bind(test_hash().to_string())
    .bind(attempts)
    .fetch_one(pool)
    .await
    .expect("seed pending scan row")
}

// ---------------------------------------------------------------------------
// Reading the row back
// ---------------------------------------------------------------------------

/// The columns an operator reads off a scan row.
#[derive(Debug)]
struct RowState {
    status: String,
    attempts: i32,
    last_error: Option<String>,
    locked_by: Option<String>,
    result_summary: Option<serde_json::Value>,
    /// Whether `locked_until` is still in the future — i.e. whether the
    /// backoff the dispatcher wrote is holding the row back from a claim.
    locked_until_in_future: Option<bool>,
}

async fn row_state(pool: &PgPool, job_id: Uuid) -> RowState {
    let row = sqlx::query(
        "SELECT status::text AS status, attempts, last_error, locked_by, result_summary, \
                locked_until > now() AS future \
         FROM public.jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_one(pool)
    .await
    .expect("read back the scan row");
    RowState {
        status: row.get("status"),
        attempts: row.get("attempts"),
        last_error: row.get("last_error"),
        locked_by: row.get("locked_by"),
        result_summary: row.get("result_summary"),
        locked_until_in_future: row.get("future"),
    }
}

async fn backdate_lock(pool: &PgPool, job_id: Uuid) {
    sqlx::query("UPDATE public.jobs SET locked_until = now() - interval '1 second' WHERE id = $1")
        .bind(job_id)
        .execute(pool)
        .await
        .expect("backdate the reschedule backoff");
}

// ---------------------------------------------------------------------------
// The stub handler
// ---------------------------------------------------------------------------

/// Returns a fixed [`TaskOutcome`] per invocation — the outcomes
/// `ScanTaskHandler` produces from a `ScanRowDisposition`.
struct FixedOutcome {
    outcome: TaskOutcome,
}

impl TaskHandler for FixedOutcome {
    fn kind(&self) -> &'static str {
        "scan"
    }

    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        let outcome = self.outcome.clone();
        Box::pin(async move { Ok(outcome) })
    }
}

/// Run the real dispatcher over whatever `kind='scan'` rows are claimable,
/// with a handler that returns `outcome`, then cancel.
///
/// Goes through `run` rather than a private entry point so the claim, the
/// lease renewal and the outcome write are all the production ones.
async fn dispatch_scan_rows(pool: &PgPool, outcome: TaskOutcome) {
    let jobs: Arc<dyn JobsRepository> = Arc::new(PgJobsRepository::new(pool.clone()));
    let event_store = Arc::new(PgEventStore::new(pool.clone()).await.expect("event store"));
    let (tx, _rx) = tokio::sync::broadcast::channel(64);
    let publisher = Arc::new(hort_app::event_store_publisher::EventStorePublisher::new(
        event_store,
        tx,
    ));
    let mut dispatcher = TaskDispatcher::new(
        jobs,
        publisher,
        // Required by the constructor so no worker dispatches destructive
        // work without a live authority re-check. `scan` is not a
        // destructive kind, so it is never consulted here.
        Arc::new(DestructiveTaskReauthorizer::new(
            Arc::new(PgUserRepository::new(pool.clone())),
            Arc::new(PgPermissionGrantRepository::new(pool.clone())),
        )),
        "it-scan-owner",
        LEASE,
        0, // poll as fast as the test can drive it
        4,
        ATTEMPT_CAP,
    );
    assert_eq!(
        dispatcher.attempt_cap(),
        ATTEMPT_CAP,
        "the dispatcher must close rows out against the cap it was given"
    );
    dispatcher.register(Arc::new(FixedOutcome { outcome }), 1);

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });
    tokio::time::sleep(Duration::from_millis(250)).await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("dispatcher shuts down on cancellation");
}

// ---------------------------------------------------------------------------
// Acceptance 1 + 6 — a transient failure with budget left survives as a
// scheduled retry, and the next claim charges the next attempt
// ---------------------------------------------------------------------------

/// A scan whose composition fails with budget left leaves the row
/// `pending`, unlocked, carrying the compose message — and the backoff
/// holds it back until it elapses, at which point the claim charges the
/// next attempt.
///
/// This is the reported incident's row, and the assertion that used to
/// fail: before the row had one owner it read `status='completed'` with
/// `attempts` frozen at 1 and the compose error still in `last_error`.
///
/// The second half is the counter-assertion the fix needs: a change that
/// re-fenced the result write on `status` instead of removing the second
/// writer would be green on "the row stays pending" and still leave two
/// owners. `attempts` advancing 1 → 2 across two claims is what proves the
/// retry is a real re-execution rather than a row that merely looks
/// pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial(hort_pg_db)]
async fn a_transient_scan_failure_with_budget_left_stays_a_scheduled_retry() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined")).await;
    let job_id = seed_pending_scan(&pool, artifact, repo, 0).await;

    dispatch_scan_rows(&pool, TaskOutcome::fail(COMPOSE_ERROR, true)).await;

    let state = row_state(&pool, job_id).await;
    assert_eq!(
        state.status, "pending",
        "a scan with budget left owes the artifact a verdict and must stay claimable; \
         got {state:?}"
    );
    assert_eq!(state.attempts, 1, "the first claim charged attempt 1");
    assert_eq!(state.last_error.as_deref(), Some(COMPOSE_ERROR));
    assert_eq!(
        state.locked_by, None,
        "a rescheduled row is unlocked so a sibling replica can take it"
    );
    assert_eq!(
        state.locked_until_in_future,
        Some(true),
        "the backoff is in the future, so the row is not immediately re-claimable"
    );

    // Still held by the backoff: the real claim statement must not return it.
    let jobs = PgJobsRepository::new(pool.clone());
    let claimed = jobs
        .claim_pending_by_kinds(&["scan"], 10, "it-second-worker", LEASE)
        .await
        .expect("claim_pending_by_kinds");
    assert!(
        !claimed.iter().any(|j| j.id == job_id),
        "the backoff must hold the row back from an immediate re-claim"
    );

    // Once it elapses, the retry is a real second execution.
    backdate_lock(&pool, job_id).await;
    dispatch_scan_rows(&pool, TaskOutcome::fail(COMPOSE_ERROR, true)).await;

    let state = row_state(&pool, job_id).await;
    assert_eq!(
        state.attempts, 2,
        "`attempts` advances per claim — a fix that re-fenced on status instead of removing \
         the second writer would leave this at 1 while the row still read pending; got {state:?}"
    );
    assert_eq!(state.status, "pending", "budget is still left at 2 of 5");
}

// ---------------------------------------------------------------------------
// Acceptance 2 — the budget spent leaves a terminal row
// ---------------------------------------------------------------------------

/// The same transient failure with the budget spent leaves the row
/// `failed`, keeping the error that failed it.
///
/// The artifact half of this boundary — an already-`quarantined` artifact
/// stays quarantined with no `ScanIndeterminate`, any other status routes
/// through `record_scan_indeterminate` first — is unchanged by the
/// single-owner change and is asserted in
/// `hort-app`'s `scan_orchestration` tests, where the scan can be driven
/// without a database.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial(hort_pg_db)]
async fn a_transient_scan_failure_with_the_budget_spent_leaves_a_terminal_row() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined")).await;
    // Claimed at the cap: the claim increments, so seeding one below it
    // puts the execution exactly on the boundary.
    let job_id = seed_pending_scan(&pool, artifact, repo, AT_CAP_SEED).await;

    dispatch_scan_rows(&pool, TaskOutcome::fail(COMPOSE_ERROR, true)).await;

    let state = row_state(&pool, job_id).await;
    assert_eq!(
        state.status, "failed",
        "a spent budget is a permanent, operator-visible failed row; got {state:?}"
    );
    assert_eq!(state.attempts, AT_CAP_SEED + 1);
    assert_eq!(
        state.last_error.as_deref(),
        Some(COMPOSE_ERROR),
        "the row keeps the error that failed it"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 3 — NothingAnalysable is terminal at the first attempt
// ---------------------------------------------------------------------------

/// A disposition that is terminal by the scan's own verdict goes terminal
/// immediately, with the whole budget still unspent.
///
/// `ScanRowDisposition::Failed` maps to `retry: false`, and the row has to
/// honour that rather than spending five backoffs on an abstention that
/// will abstain again — the artifact's kind and the backends' analyzers are
/// both fixed. This is also where the old defect was loudest: the blanket
/// `TaskOutcome::Completed` made this row read `completed`, which is the
/// one word that must never describe a scan with no verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial(hort_pg_db)]
async fn a_scan_with_nothing_to_analyse_is_terminal_at_the_first_attempt() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined")).await;
    let job_id = seed_pending_scan(&pool, artifact, repo, 0).await;
    let reason = "no scan backend could analyse artifact (kind npm_tarball): \
                  trivy=no_analyzer_matched";

    dispatch_scan_rows(&pool, TaskOutcome::fail(reason, false)).await;

    let state = row_state(&pool, job_id).await;
    assert_eq!(
        state.status, "failed",
        "a deterministic abstention is terminal on the first attempt; got {state:?}"
    );
    assert_eq!(
        state.attempts, 1,
        "and it must not spend the retry budget first"
    );
    assert_eq!(state.last_error.as_deref(), Some(reason));
    assert!(
        state.result_summary.is_none(),
        "a row with no verdict must not carry a result summary; got {state:?}"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 4 — the happy path is unchanged
// ---------------------------------------------------------------------------

/// A completed scan completes the row with the same `result_summary` keys
/// the handler has always built: `scanner`, `finding_count`, `assessment`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial(hort_pg_db)]
async fn a_completed_scan_completes_the_row_with_the_same_summary_keys() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined")).await;
    let job_id = seed_pending_scan(&pool, artifact, repo, 0).await;
    let summary = serde_json::json!({
        "scanner": "trivy",
        "finding_count": 2,
        "assessment": "analysed",
    });

    dispatch_scan_rows(
        &pool,
        TaskOutcome::Completed {
            result_summary: summary.clone(),
        },
    )
    .await;

    let state = row_state(&pool, job_id).await;
    assert_eq!(state.status, "completed", "got {state:?}");
    assert_eq!(
        state.result_summary.as_ref(),
        Some(&summary),
        "the happy path's summary keys are unchanged; got {state:?}"
    );
    assert_eq!(state.last_error, None);
}

// ---------------------------------------------------------------------------
// A persistence failure at the cap leaves a recoverable obligation
// ---------------------------------------------------------------------------

/// When `record_outcome` fails, no verdict was recorded — so the handler
/// reports a retryable failure, and at the cap the dispatcher writes
/// `failed`. The obligation must not disappear with that write.
///
/// It does not, and this is what makes the terminal row recoverable rather
/// than silent: the artifact's own state was never moved, so it is still a
/// rescan candidate. For a `quarantined` artifact that is
/// `select_stranded`, whose predicate is exactly "quarantined, last scan
/// job `failed` or absent" — asserted here against the real query rather
/// than inferred from the SQL. The verdict-less terminal row is itself the
/// signal that re-picks the artifact once the scanner recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial(hort_pg_db)]
async fn a_persistence_failure_at_the_cap_leaves_a_quarantined_artifact_stranded_not_lost() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined")).await;
    let job_id = seed_pending_scan(&pool, artifact, repo, AT_CAP_SEED).await;

    // Exactly what `ScanTaskHandler::run` returns when `record_outcome`
    // errors: a retryable failure naming the undischarged obligation.
    dispatch_scan_rows(
        &pool,
        TaskOutcome::fail("record_outcome failed: event store unavailable", true),
    )
    .await;

    let state = row_state(&pool, job_id).await;
    assert_eq!(state.status, "failed", "got {state:?}");

    // The artifact kept its status — no verdict was written, and none was
    // invented.
    let status: Option<String> =
        sqlx::query_scalar("SELECT quarantine_status::text FROM public.artifacts WHERE id = $1")
            .bind(artifact)
            .fetch_one(&pool)
            .await
            .expect("read back the artifact status");
    assert_eq!(status.as_deref(), Some("quarantined"));

    // And the sweep still sees it.
    let candidates = PgRescanCandidatesRepository::new(pool.clone())
        .select_stranded(50)
        .await
        .expect("select_stranded");
    assert!(
        candidates.iter().any(|c| c.artifact_id == artifact),
        "a terminal row with no verdict behind it must leave the artifact visible to the \
         stranded-rescan sweep; otherwise the obligation is lost and the artifact is held \
         forever with nobody owing it an answer. Got {} candidates",
        candidates.len()
    );
}

/// The permissive-default half of the same case: an artifact with no
/// quarantine status and no completed scan stays visible to
/// `select_eligible`, whose `last_scan_at IS NULL` arm admits exactly an
/// artifact no scan ever finished.
///
/// `select_stranded` would not find this one — it requires
/// `quarantine_status = 'quarantined'` — so the two queries between them
/// are what keep a verdict-less terminal row from being the end of the
/// story, and both halves are asserted rather than one standing in for the
/// other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial(hort_pg_db)]
async fn a_persistence_failure_at_the_cap_leaves_a_permissive_artifact_rescan_eligible() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, None).await;
    let job_id = seed_pending_scan(&pool, artifact, repo, AT_CAP_SEED).await;

    dispatch_scan_rows(
        &pool,
        TaskOutcome::fail("record_outcome failed: event store unavailable", true),
    )
    .await;

    assert_eq!(row_state(&pool, job_id).await.status, "failed");

    let candidates = PgRescanCandidatesRepository::new(pool.clone())
        .select_eligible(50, chrono::Utc::now())
        .await
        .expect("select_eligible");
    assert!(
        candidates.iter().any(|c| c.artifact_id == artifact),
        "an artifact no scan ever completed must stay rescan-eligible after a verdict-less \
         terminal row. Got {} candidates",
        candidates.len()
    );
}

// ---------------------------------------------------------------------------
// The sweep spends the same budget
// ---------------------------------------------------------------------------

/// The dead-worker half of the budget reads the same configured cap.
///
/// `requeue_abandoned` is the only code that runs for a row whose handler
/// never returned, and it takes the cap as an argument. A cap threaded into
/// only the returned-failure path would let a crashed worker's row be
/// re-driven past a budget an identical row whose handler returned had
/// already spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial(hort_pg_db)]
async fn the_abandoned_lease_sweep_fails_a_scan_row_at_the_same_cap() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    assert!(
        REQUEUE_ON_LEASE_EXPIRY_KINDS.contains(&"scan"),
        "this test is only about what it claims while `scan` is in the requeue allow-list"
    );
    let repo = seed_repo(&pool).await;
    let artifact = seed_artifact(&pool, repo, Some("quarantined")).await;
    let job_id = seed_pending_scan(&pool, artifact, repo, 0).await;

    // A worker that claimed the row and never came back: `running`, with a
    // lease that lapsed long enough ago that the grace window elapsed too.
    sqlx::query(
        "UPDATE public.jobs SET status = 'running', attempts = $2, locked_by = 'dead-worker', \
         locked_until = now() - interval '1 hour' WHERE id = $1",
    )
    .bind(job_id)
    .bind(AT_CAP_SEED + 1)
    .execute(&pool)
    .await
    .expect("strand the row in running");

    let resolved = PgJobsRepository::new(pool.clone())
        .requeue_abandoned(
            REQUEUE_ON_LEASE_EXPIRY_KINDS,
            Duration::from_secs(1),
            ATTEMPT_CAP,
            100,
        )
        .await
        .expect("requeue_abandoned");
    assert!(
        resolved.iter().any(|r| r.id == job_id),
        "the sweep must resolve a row stranded past its lease plus the grace"
    );

    let state = row_state(&pool, job_id).await;
    assert_eq!(
        state.status, "failed",
        "a stranded row at the cap is failed terminally rather than re-driven into the same \
         crash; got {state:?}"
    );
}
