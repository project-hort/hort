//! Abandoned-lease recovery — `renew_lease` + `requeue_abandoned`
//! against a real PostgreSQL instance.
//!
//! ## The gap under test
//!
//! Both claim statements (`CLAIM_PENDING_BY_KINDS_SQL`,
//! `claim_scan_jobs`) select `status = 'pending'` only; their
//! `locked_until IS NULL OR locked_until < now()` clause re-claims a
//! *pending* row whose not-before has passed and never looks at a
//! `running` one. So a worker that dies holding a claim leaves the row
//! on `running` forever. For `kind = 'scan'` that is not clutter but a
//! lost capability: `jobs_scan_unique` is `(artifact_id) WHERE kind =
//! 'scan' AND status IN ('pending','running')`, so while the abandoned
//! row sits there **no further scan job for that artifact can ever be
//! enqueued** and both rescan predicates skip the artifact as in-flight.
//!
//! [`an_artifact_with_an_abandoned_scan_row_is_scannable_again`] is the
//! acceptance test; everything else here supports it.
//!
//! `DATABASE_URL`-gated per the project convention: when unset every
//! test early-returns. Every test that acquires a connection carries
//! `#[serial(hort_pg_db)]` — the migration set's `CREATE ROLE` and the
//! stale-database sweeper are cluster-global, so a per-test database is
//! not isolation from a concurrently-running sibling.
//!
//! ```bash
//! DATABASE_URL=postgresql://… \
//!   cargo test -p hort-adapters-postgres --test lease_expiry_requeue
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::time::Duration;

use serial_test::serial;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_domain::ports::jobs_repository::{
    JobsRepository, RequeueOutcome, ResultWriteOutcome, REQUEUE_ON_LEASE_EXPIRY_KINDS,
};
use hort_domain::types::ContentHash;

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

/// Seed a `kind='scan'` row already in `running` with a lease that
/// lapsed `lapsed_secs` ago — exactly the state a worker killed
/// mid-scan leaves behind. Returns `(job_id, artifact_id)`.
async fn seed_abandoned_scan(pool: &PgPool, attempts: i32, lapsed_secs: i64) -> (Uuid, Uuid) {
    let artifact_id = Uuid::new_v4();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO public.jobs \
            (kind, artifact_id, repository_id, content_hash, format, priority, status, \
             attempts, locked_by, locked_until) \
         VALUES ('scan', $1, $2, $3, 'npm', 0, 'running', $4, 'dead-worker', \
                 now() - make_interval(secs => $5)) \
         RETURNING id",
    )
    .bind(artifact_id)
    .bind(Uuid::new_v4())
    .bind(test_hash().to_string())
    .bind(attempts)
    .bind(lapsed_secs as f64)
    .fetch_one(pool)
    .await
    .expect("seed abandoned scan row");
    (id, artifact_id)
}

/// Seed a non-scan row in `running` with a lease lapsed `lapsed_secs`
/// ago. `kind` is a bare `jobs.kind` literal with no typed columns.
async fn seed_abandoned(pool: &PgPool, kind: &str, attempts: i32, lapsed_secs: i64) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO public.jobs (kind, status, attempts, locked_by, locked_until) \
         VALUES ($1, 'running', $2, 'dead-worker', now() - make_interval(secs => $3)) \
         RETURNING id",
    )
    .bind(kind)
    .bind(attempts)
    .bind(lapsed_secs as f64)
    .fetch_one(pool)
    .await
    .expect("seed abandoned row")
}

async fn read_row(pool: &PgPool, id: Uuid) -> (String, i32, Option<String>, Option<String>) {
    let row = sqlx::query(
        "SELECT status, attempts, locked_by, last_error FROM public.jobs WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("re-read job row");
    (
        row.try_get("status").expect("status"),
        row.try_get("attempts").expect("attempts"),
        row.try_get("locked_by").expect("locked_by"),
        row.try_get("last_error").expect("last_error"),
    )
}

// ---------------------------------------------------------------------------
// Acceptance — the capability the abandoned row takes away comes back
// ---------------------------------------------------------------------------

/// An artifact whose scan row was abandoned in `running` is scannable
/// again after the sweep.
///
/// Three moves, and the middle one is the whole point of the unit:
///
/// 1. `enqueue_scan` for that artifact is **rejected** while the
///    abandoned row sits in `running` — `jobs_scan_unique` covers
///    `status IN ('pending','running')`, so the artifact is not merely
///    un-scanned, it is unenqueueable, permanently and silently.
/// 2. The sweep returns the row to `pending`.
/// 3. The row is claimable again, which is what "scannable" means for
///    the pipeline: the claim is the only thing that moves a scan
///    forward.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_artifact_with_an_abandoned_scan_row_is_scannable_again() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let (job_id, artifact_id) = seed_abandoned_scan(&pool, 1, 3_600).await;

    // 1. The artifact is un-enqueueable while the row is stranded.
    let blocked = repo
        .enqueue_scan(
            artifact_id,
            Uuid::new_v4(),
            &test_hash(),
            "npm",
            0,
            "manual",
        )
        .await;
    assert!(
        blocked.is_err(),
        "the abandoned running row must block a fresh scan enqueue — if it does not, \
         jobs_scan_unique changed and this test is no longer proving the trap exists"
    );

    // And nothing claims it: the claim predicate is `status = 'pending'`.
    let pre = repo
        .claim_pending_by_kinds(&["scan"], 10, "live-worker", Duration::from_secs(900))
        .await
        .expect("claim");
    assert!(
        pre.is_empty(),
        "no claim statement selects a 'running' row — that is the gap this unit closes"
    );

    // 2. Sweep it.
    let resolved = repo
        .requeue_abandoned(
            REQUEUE_ON_LEASE_EXPIRY_KINDS,
            Duration::from_secs(900),
            5,
            100,
        )
        .await
        .expect("requeue_abandoned");
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].id, job_id);
    assert_eq!(resolved[0].outcome, RequeueOutcome::Requeued);

    // 3. Claimable again. `locked_until` carries a short not-before, so
    //    wind it back rather than sleeping through it.
    sqlx::query("UPDATE public.jobs SET locked_until = now() - interval '1 second' WHERE id = $1")
        .bind(job_id)
        .execute(&pool)
        .await
        .expect("expire the requeue not-before");

    let claimed = repo
        .claim_pending_by_kinds(&["scan"], 10, "live-worker", Duration::from_secs(900))
        .await
        .expect("claim");
    assert_eq!(
        claimed.iter().filter(|j| j.id == job_id).count(),
        1,
        "the requeued scan row must be claimable again"
    );
}

// ---------------------------------------------------------------------------
// The retry budget after a requeue
// ---------------------------------------------------------------------------

/// The sweep does not spend the budget; the claim does.
///
/// `attempts` is incremented by the claim statement, so a requeued row
/// is counted on its next claim exactly as a `reschedule`d one is. A
/// sweep that also incremented would double-charge a row for one
/// execution attempt.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_requeue_leaves_attempts_alone_and_the_next_claim_charges_it() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let (job_id, _) = seed_abandoned_scan(&pool, 2, 3_600).await;

    let resolved = repo
        .requeue_abandoned(
            REQUEUE_ON_LEASE_EXPIRY_KINDS,
            Duration::from_secs(900),
            5,
            100,
        )
        .await
        .expect("requeue_abandoned");
    assert_eq!(resolved[0].attempts, 2, "the sweep reports what it saw");

    let (status, attempts, locked_by, last_error) = read_row(&pool, job_id).await;
    assert_eq!(status, "pending");
    assert_eq!(
        attempts, 2,
        "the sweep must not charge an attempt of its own"
    );
    assert_eq!(locked_by, None, "the dead worker's claim is released");
    assert!(
        last_error.expect("last_error").contains("lease expired"),
        "the row has to say why it changed state — nothing else recorded it"
    );

    sqlx::query("UPDATE public.jobs SET locked_until = now() - interval '1 second' WHERE id = $1")
        .bind(job_id)
        .execute(&pool)
        .await
        .expect("expire the requeue not-before");
    repo.claim_pending_by_kinds(&["scan"], 10, "live-worker", Duration::from_secs(900))
        .await
        .expect("claim");

    let (_, attempts_after, _, _) = read_row(&pool, job_id).await;
    assert_eq!(
        attempts_after, 3,
        "the CLAIM is what spends the budget, so a requeued row costs exactly one attempt"
    );
}

/// At the attempt cap the sweep fails the row terminally instead of
/// re-driving it.
///
/// This is the only place the budget can be enforced for a row whose
/// handler never returned: the scan orchestrator's `attempts >=
/// max_attempts` branch and the dispatcher's `TaskOutcome::Failed` arms
/// both require the handler to come back, which is exactly what a task
/// that kills its worker does not do. Without the cap here, a crash loop
/// would be re-driven forever while `attempts` climbed with nothing
/// reading it.
///
/// The row is **failed, not deleted**. For `kind='scan'` that hands the
/// artifact to the stranded-scan recovery sweep, whose predicate is a
/// newest scan job in `failed` — the two mechanisms compose rather than
/// duplicating each other.
#[tokio::test]
#[serial(hort_pg_db)]
async fn at_the_attempt_cap_the_sweep_fails_the_row_instead_of_requeueing_forever() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let (at_cap, at_cap_artifact) = seed_abandoned_scan(&pool, 5, 3_600).await;
    let (over_cap, _) = seed_abandoned_scan(&pool, 9, 3_600).await;
    let (below_cap, _) = seed_abandoned_scan(&pool, 4, 3_600).await;

    let resolved = repo
        .requeue_abandoned(
            REQUEUE_ON_LEASE_EXPIRY_KINDS,
            Duration::from_secs(900),
            5,
            100,
        )
        .await
        .expect("requeue_abandoned");
    assert_eq!(resolved.len(), 3);

    for (id, expected_status, expected_outcome) in [
        (at_cap, "failed", RequeueOutcome::RetriesExhausted),
        (over_cap, "failed", RequeueOutcome::RetriesExhausted),
        (below_cap, "pending", RequeueOutcome::Requeued),
    ] {
        let (status, _, _, _) = read_row(&pool, id).await;
        assert_eq!(status, expected_status, "row {id}");
        let reported = resolved
            .iter()
            .find(|r| r.id == id)
            .expect("every swept row is reported");
        assert_eq!(reported.outcome, expected_outcome, "row {id}");
    }

    // The failed row is retained, so a late completion from the original
    // worker still lands on it rather than on nothing. The sweep left
    // `attempts` at 5, and a `failed` row is not claimable, so nothing
    // can have moved the row past the execution that is still out
    // there — the result-write fence admits it.
    assert_eq!(
        repo.mark_completed(at_cap, 5, serde_json::json!({"late": true}))
            .await
            .expect("a late completion must still find its row"),
        ResultWriteOutcome::Applied,
    );
    let (status, _, _, _) = read_row(&pool, at_cap).await;
    assert_eq!(status, "completed");

    // And the terminal row released the artifact from `jobs_scan_unique`,
    // which is what lets the stranded-scan recovery re-enqueue.
    repo.enqueue_scan(
        at_cap_artifact,
        Uuid::new_v4(),
        &test_hash(),
        "npm",
        0,
        "cron",
    )
    .await
    .expect("a terminal row frees the artifact for a fresh scan");
}

// ---------------------------------------------------------------------------
// The discriminator — what the sweep refuses to touch
// ---------------------------------------------------------------------------

/// A row whose lease has lapsed but not yet by the grace window is left
/// alone. The grace is the margin for a renewal that is alive but late.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_lease_inside_the_grace_window_is_not_swept() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let (recent, _) = seed_abandoned_scan(&pool, 0, 60).await;
    let (old, _) = seed_abandoned_scan(&pool, 0, 3_600).await;

    let resolved = repo
        .requeue_abandoned(
            REQUEUE_ON_LEASE_EXPIRY_KINDS,
            Duration::from_secs(900),
            5,
            100,
        )
        .await
        .expect("requeue_abandoned");

    let ids: Vec<Uuid> = resolved.iter().map(|r| r.id).collect();
    assert!(
        !ids.contains(&recent),
        "60 s past the lease is inside a 900 s grace"
    );
    assert!(
        ids.contains(&old),
        "an hour past the lease is well outside it"
    );
    let (status, _, _, _) = read_row(&pool, recent).await;
    assert_eq!(
        status, "running",
        "an in-grace row keeps its claim untouched"
    );
}

/// A `running` row with a NULL lease is left alone.
///
/// Neither claim statement can produce one, so "no lease" is a state
/// nobody understands rather than "a lease that lapsed long ago";
/// sweeping it would be acting on a row whose history is unexplained.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_running_row_with_no_lease_at_all_is_left_alone() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO public.jobs (kind, status, locked_by, locked_until) \
         VALUES ('noop', 'running', 'w', NULL) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed lease-less running row");

    let resolved = repo
        .requeue_abandoned(
            REQUEUE_ON_LEASE_EXPIRY_KINDS,
            Duration::from_secs(1),
            5,
            100,
        )
        .await
        .expect("requeue_abandoned");

    assert!(resolved.iter().all(|r| r.id != id));
    let (status, _, _, _) = read_row(&pool, id).await;
    assert_eq!(status, "running");
}

/// An excluded kind's abandoned row stays where it is.
///
/// `eventstore-archive` is the sharpest case: `seal_and_remove`'s
/// `StreamSealed` append has no internal wait bound and is safe only
/// because at most one is in flight cluster-wide, and the worker
/// semaphore that delivers part of that guarantee is per *process* — a
/// requeue claimed by a sibling replica walks around it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_excluded_kind_is_never_requeued() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let archive = seed_abandoned(&pool, "eventstore-archive", 0, 86_400).await;
    let purge = seed_abandoned(&pool, "retention-purge", 0, 86_400).await;
    let noop = seed_abandoned(&pool, "noop", 0, 86_400).await;

    let resolved = repo
        .requeue_abandoned(
            REQUEUE_ON_LEASE_EXPIRY_KINDS,
            Duration::from_secs(900),
            5,
            100,
        )
        .await
        .expect("requeue_abandoned");

    let ids: Vec<Uuid> = resolved.iter().map(|r| r.id).collect();
    assert!(!ids.contains(&archive));
    assert!(!ids.contains(&purge));
    assert!(
        ids.contains(&noop),
        "an in-policy kind is swept in the same pass"
    );
    for excluded in [archive, purge] {
        let (status, _, locked_by, _) = read_row(&pool, excluded).await;
        assert_eq!(status, "running");
        assert_eq!(locked_by.as_deref(), Some("dead-worker"));
    }
}

/// An empty kind list sweeps nothing and issues no query — the
/// fail-safe shape for a caller that has filtered its allow-list down to
/// nothing.
#[tokio::test]
#[serial(hort_pg_db)]
async fn an_empty_kind_list_sweeps_nothing() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let id = seed_abandoned(&pool, "noop", 0, 86_400).await;

    let resolved = repo
        .requeue_abandoned(&[], Duration::from_secs(1), 5, 100)
        .await
        .expect("requeue_abandoned");

    assert!(resolved.is_empty());
    let (status, _, _, _) = read_row(&pool, id).await;
    assert_eq!(status, "running");
}

/// The batch bound holds, and the sweep takes the longest-stranded rows
/// first — so a batch-limited pass drains the worst backlog rather than
/// an arbitrary slice of it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_sweep_is_batch_bounded_and_takes_the_oldest_lapse_first() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let oldest = seed_abandoned(&pool, "noop", 0, 86_400).await;
    let middle = seed_abandoned(&pool, "noop", 0, 7_200).await;
    let _newest = seed_abandoned(&pool, "noop", 0, 3_600).await;

    let resolved = repo
        .requeue_abandoned(
            REQUEUE_ON_LEASE_EXPIRY_KINDS,
            Duration::from_secs(900),
            5,
            2,
        )
        .await
        .expect("requeue_abandoned");

    assert_eq!(resolved.len(), 2, "batch_size bounds the pass");
    let ids: Vec<Uuid> = resolved.iter().map(|r| r.id).collect();
    assert!(ids.contains(&oldest) && ids.contains(&middle));
}

// ---------------------------------------------------------------------------
// renew_lease
// ---------------------------------------------------------------------------

/// A renewal by the holding worker pushes `locked_until` out and keeps
/// the row out of the sweep's reach. This is the mechanism that makes an
/// expired lease mean "dead" rather than "slow".
#[tokio::test]
#[serial(hort_pg_db)]
async fn renewal_by_the_holder_pushes_the_lease_past_the_sweep() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let (job_id, _) = seed_abandoned_scan(&pool, 0, 3_600).await;

    assert!(
        repo.renew_lease(job_id, "dead-worker", Duration::from_secs(900))
            .await
            .expect("renew_lease"),
        "the worker named in locked_by owns the lease and may extend it"
    );

    let resolved = repo
        .requeue_abandoned(
            REQUEUE_ON_LEASE_EXPIRY_KINDS,
            Duration::from_secs(900),
            5,
            100,
        )
        .await
        .expect("requeue_abandoned");
    assert!(
        resolved.iter().all(|r| r.id != job_id),
        "a renewed row is a live row — a task slower than its lease must never be swept"
    );
}

/// A renewal from a worker that does not hold the row changes nothing
/// and reports `false`.
///
/// This is the fence. After a sweep hands the row to a sibling, the
/// original worker's renewal must not extend the sibling's lease — and
/// the `false` is how the original finds out its execution is no longer
/// the authoritative one.
#[tokio::test]
#[serial(hort_pg_db)]
async fn renewal_by_a_worker_that_lost_the_row_is_refused() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let (job_id, _) = seed_abandoned_scan(&pool, 0, 3_600).await;

    assert!(
        !repo
            .renew_lease(job_id, "some-other-worker", Duration::from_secs(900))
            .await
            .expect("renew_lease"),
        "a worker that does not hold the claim must not be able to extend it"
    );

    let before: Option<String> =
        sqlx::query_scalar("SELECT locked_by FROM public.jobs WHERE id=$1")
            .bind(job_id)
            .fetch_one(&pool)
            .await
            .expect("read locked_by");
    assert_eq!(
        before.as_deref(),
        Some("dead-worker"),
        "ownership unchanged"
    );
}

/// A renewal racing the outcome write cannot resurrect a lease on a row
/// that is no longer running.
///
/// Without the `status = 'running'` predicate a late renewal would leave
/// a `completed` row carrying a future `locked_until`, which makes the
/// sweep's own predicate ambiguous for anyone reading the table.
#[tokio::test]
#[serial(hort_pg_db)]
async fn renewal_refuses_a_row_that_is_no_longer_running() {
    let Some(pool) = maybe_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());
    let (job_id, _) = seed_abandoned_scan(&pool, 0, 60).await;
    repo.mark_completed(job_id, 0, serde_json::Value::Null)
        .await
        .expect("mark_completed");

    assert!(
        !repo
            .renew_lease(job_id, "dead-worker", Duration::from_secs(900))
            .await
            .expect("renew_lease"),
        "a terminal row has no lease to extend"
    );
}
