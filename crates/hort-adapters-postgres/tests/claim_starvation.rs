//! Regression tests for the silent claim starvation of an unregistered
//! job kind, and for the claimed-but-not-dispatched row loss found
//! alongside it.
//!
//! **The live contradiction.** On a compose stack, `provenance-verify`
//! rows stopped being claimed cold: ~1450 rows accumulated over 33
//! minutes, every one of them `pending, attempts=0, locked_until NULL`,
//! nothing `running`, no panic and no `ERROR` anywhere — while the SAME
//! dispatcher claimed and completed `quarantine-release-sweep` rows every
//! tick. Those rows satisfy every predicate of `CLAIM_PENDING_BY_KINDS_SQL`
//! as written, so one premise had to be false at runtime.
//!
//! It is the `kind = ANY($1::text[])` premise. The `$1` array is
//! `TaskDispatcher::run`'s registered-kind list, and the composition root
//! registers `ProvenanceVerifyHandler` behind a backend gate that, when it
//! declines, logs one `info!` and registers nothing. From that moment the
//! kind is not in the claim's array, so no row of it is ever selected —
//! and every downstream signal is silent by construction.
//! [`unregistered_kind_reproduces_the_live_row_signature`] reproduces
//! exactly that jobs-table shape through the real dispatcher and the real
//! adapter, and pins the diagnostic that now exposes it.
//!
//! The two priority-race candidates do NOT produce that shape and are
//! pinned as such by
//! [`older_same_priority_backlog_out_sorts_a_newer_sweep_row`]: the S4
//! re-enqueue priority (`CLEARANCE_VERIFY_PRIORITY = 10`) EQUALS the
//! scheduled-sweep priority (`CRON_PRIORITY = 10`), and the provenance
//! rows are the older ones, so a priority/`LIMIT` race would starve the
//! SWEEP, not the verifies — the inverse of what was observed.
//!
//! `DATABASE_URL`-gated: every test self-skips when it is unset.

#![allow(clippy::expect_used)]

use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use hort_adapters_postgres::event_store::PgEventStore;
use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_app::task_dispatcher::TaskDispatcher;
use hort_domain::error::DomainResult;
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

/// `deploy/compose/docker-compose.yml` — `HORT_SCANNER_BATCH_SIZE`.
const REAL_BATCH_SIZE: u16 = 4;
/// `CLEARANCE_VERIFY_PRIORITY` (`hort-app::ingest_use_case`) — the S4
/// expiry-backstop re-enqueue priority, and `CRON_PRIORITY`
/// (`hort-server::cli::enqueue_quarantine_release_sweep`). Identical by
/// construction; that identity is what rules the priority race out.
const CLEARANCE_AND_CRON_PRIORITY: i16 = 10;

async fn isolated_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    hort_adapters_postgres::test_support::isolated_db_from(&url).await
}

async fn seed_provenance(pool: &PgPool, n: usize, priority: i16, age_secs: i64) {
    for _ in 0..n {
        // Mirrors `enqueue_provenance_verify_in_tx` / the S4
        // `enqueue_task("provenance-verify", …)` row shape.
        let params = serde_json::json!({ "artifact_id": Uuid::new_v4() });
        sqlx::query(
            "INSERT INTO public.jobs (kind, params, priority, trigger_source, status, \
             created_at, updated_at) VALUES ('provenance-verify', $1, $2, 'ingest', 'pending', \
             now() - make_interval(secs => $3), now() - make_interval(secs => $3))",
        )
        .bind(&params)
        .bind(priority)
        .bind(age_secs as f64)
        .execute(pool)
        .await
        .expect("seed provenance-verify row");
    }
}

async fn count_where(pool: &PgPool, predicate: &str) -> i64 {
    // Test-local literal predicates only — no external input reaches here.
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM public.jobs WHERE {predicate}"
    )))
    .fetch_one(pool)
    .await
    .expect("count")
}

/// Minimal counting handler — stands in for a real `TaskHandler`.
struct Counting {
    kind: &'static str,
    runs: Arc<AtomicUsize>,
}

impl TaskHandler for Counting {
    fn kind(&self) -> &'static str {
        self.kind
    }
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            self.runs.fetch_add(1, Ordering::SeqCst);
            Ok(TaskOutcome::Completed {
                result_summary: serde_json::json!({}),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// F0 — the live row signature, reproduced
// ---------------------------------------------------------------------------

/// The confirmed mechanism, end to end through the real
/// `TaskDispatcher` + real `PgJobsRepository`.
///
/// A dispatcher whose registered-kind array omits `provenance-verify`
/// (what the composition root's declined provenance-backend gate
/// produces) leaves an arbitrarily large eligible backlog of that kind
/// untouched — `pending`, `attempts = 0`, `locked_until NULL`, nothing
/// `running` — while claiming and completing `quarantine-release-sweep`
/// rows on every single tick. That is the live jobs-table dump, exactly.
///
/// The assertion that matters for the FIX is the last one:
/// `eligible_pending_by_kind` now surfaces the backlog the claim query
/// structurally cannot see, which is what the dispatcher's starvation
/// audit turns into an `ERROR` + `hort_admin_tasks_starved_total`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial(hort_pg_db)]
async fn unregistered_kind_reproduces_the_live_row_signature() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let jobs: Arc<dyn JobsRepository> = Arc::new(PgJobsRepository::new(pool.clone()));
    let event_store = Arc::new(PgEventStore::new(pool.clone()).await.expect("event store"));
    let (tx, _rx) = tokio::sync::broadcast::channel(64);
    let publisher = Arc::new(hort_app::event_store_publisher::EventStorePublisher::new(
        event_store,
        tx,
    ));

    // The observed backlog, at the S4 re-enqueue priority.
    seed_provenance(&pool, 200, CLEARANCE_AND_CRON_PRIORITY, 600).await;

    let sweep_runs = Arc::new(AtomicUsize::new(0));
    let mut dispatcher = TaskDispatcher::new(
        jobs.clone(),
        publisher,
        "hort-worker-v2",
        Duration::from_secs(900),
        0, // poll as fast as the test can drive it
        REAL_BATCH_SIZE,
    );
    // The defect: NO `provenance-verify` handler is registered, so the
    // kind never enters `claim_pending_by_kinds`'s `$1` array.
    dispatcher.register(
        Arc::new(Counting {
            kind: "quarantine-release-sweep",
            runs: sweep_runs.clone(),
        }),
        1,
    );
    assert!(
        !dispatcher.registered_kinds().contains(&"provenance-verify"),
        "precondition: the provenance kind must be unregistered"
    );

    let cancel = CancellationToken::new();
    let run_cancel = cancel.clone();
    let poll = tokio::spawn(async move { dispatcher.run(run_cancel).await });

    // The compose sweep ticker: a fresh scheduled row at CRON_PRIORITY.
    for _ in 0..5 {
        jobs.enqueue_task(
            "quarantine-release-sweep",
            &serde_json::json!({}),
            None,
            CLEARANCE_AND_CRON_PRIORITY,
            "cron",
            None,
        )
        .await
        .expect("enqueue sweep");
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), poll).await;

    // --- the live dump, assertion by assertion -------------------------
    assert_eq!(
        count_where(
            &pool,
            "kind = 'provenance-verify' AND status = 'pending' AND attempts = 0 \
             AND locked_until IS NULL",
        )
        .await,
        200,
        "every provenance-verify row must still be pending/attempts=0/unlocked",
    );
    assert_eq!(
        count_where(&pool, "kind = 'provenance-verify' AND status = 'running'").await,
        0,
        "no provenance-verify row may be running — the kind was never claimed",
    );
    assert!(
        sweep_runs.load(Ordering::SeqCst) > 0,
        "the SAME dispatcher must keep claiming + completing sweep rows",
    );
    assert!(
        count_where(
            &pool,
            "kind = 'quarantine-release-sweep' AND status = 'completed'",
        )
        .await
            > 0,
        "sweep rows must reach completed",
    );

    // --- the fix: the backlog is no longer invisible --------------------
    let backlog = jobs
        .eligible_pending_by_kind()
        .await
        .expect("eligible_pending_by_kind");
    let prov = backlog
        .iter()
        .find(|b| b.kind == "provenance-verify")
        .expect("the audit must see the unclaimed kind the claim query cannot");
    assert_eq!(prov.count, 200);
}

// ---------------------------------------------------------------------------
// C2 negative — the priority race would starve the SWEEP, not the verifies
// ---------------------------------------------------------------------------

/// `ORDER BY priority DESC, created_at ASC LIMIT batch_size` with the S4
/// and cron priorities equal (both 10) resolves on `created_at`, and the
/// verify backlog is the older side. A priority/`LIMIT` starvation would
/// therefore hold back the newly-enqueued sweep row — the inverse of the
/// reported incident. Pinned so the candidate is not re-litigated.
#[tokio::test]
#[serial(hort_pg_db)]
async fn older_same_priority_backlog_out_sorts_a_newer_sweep_row() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    seed_provenance(&pool, 60, CLEARANCE_AND_CRON_PRIORITY, 600).await;
    let sweep: Uuid = sqlx::query_scalar(
        "INSERT INTO public.jobs (kind, params, priority, trigger_source, status) \
         VALUES ('quarantine-release-sweep', '{}'::jsonb, $1, 'cron', 'pending') RETURNING id",
    )
    .bind(CLEARANCE_AND_CRON_PRIORITY)
    .fetch_one(&pool)
    .await
    .expect("seed sweep row");

    let kinds = ["provenance-verify", "quarantine-release-sweep"];
    for _ in 0..5 {
        let rows = repo
            .claim_pending_by_kinds(&kinds, REAL_BATCH_SIZE, "w", Duration::from_secs(900))
            .await
            .expect("claim");
        assert!(
            rows.iter().all(|r| r.kind == "provenance-verify"),
            "the older equal-priority verify rows must win every slot: {:?}",
            rows.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
        );
    }

    let sweep_status: String = sqlx::query_scalar("SELECT status FROM public.jobs WHERE id = $1")
        .bind(sweep)
        .fetch_one(&pool)
        .await
        .expect("sweep status");
    assert_eq!(
        sweep_status, "pending",
        "the priority race starves the SWEEP here — it cannot explain starved verifies",
    );
}

// ---------------------------------------------------------------------------
// F1 property — a claimed row is never permanently lost
// ---------------------------------------------------------------------------

/// A single unprojectable row used to take its whole claimed batch down
/// with it: `collect::<DomainResult<_>>()?` propagated the first mapping
/// error out of `claim_pending_by_kinds` AFTER the claiming UPDATE had
/// committed, so up to `batch_size` healthy rows were left `running` with
/// nothing to move them back — the claim predicate selects `pending` only
/// and there is no stale-`running` reaper anywhere in the codebase.
///
/// The shape is production-reachable: `"scan"` is in `VALID_TASK_KINDS`,
/// so the admin task-invoke path's `enqueue_task` writes a `kind='scan'`
/// row with the scan-typed columns NULL, which `decide_kind_fields`
/// rejects — and the `jobs` table has no CHECK preventing it.
#[tokio::test]
#[serial(hort_pg_db)]
async fn unmappable_row_does_not_strand_the_rest_of_its_claimed_batch() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    // The poison row: kind='scan' with no scan-typed columns, and the
    // oldest of its priority tier so it lands in the first batch.
    let poison: Uuid = sqlx::query_scalar(
        "INSERT INTO public.jobs (kind, params, priority, trigger_source, status, created_at) \
         VALUES ('scan', '{}'::jsonb, $1, 'manual', 'pending', now() - interval '1 hour') \
         RETURNING id",
    )
    .bind(CLEARANCE_AND_CRON_PRIORITY)
    .fetch_one(&pool)
    .await
    .expect("seed poison scan row");
    seed_provenance(&pool, 8, CLEARANCE_AND_CRON_PRIORITY, 1800).await;

    let kinds = ["scan", "provenance-verify"];
    let claimed = repo
        .claim_pending_by_kinds(&kinds, REAL_BATCH_SIZE, "w", Duration::from_secs(900))
        .await
        .expect("the claim must survive an unmappable row, not fail the whole batch");

    assert_eq!(
        claimed.len(),
        usize::from(REAL_BATCH_SIZE) - 1,
        "every mappable row in the batch must still be dispatched",
    );
    assert!(
        claimed.iter().all(|r| r.kind == "provenance-verify"),
        "only the poison row may be withheld",
    );

    let (status, last_error): (String, Option<String>) =
        sqlx::query_as("SELECT status, last_error FROM public.jobs WHERE id = $1")
            .bind(poison)
            .fetch_one(&pool)
            .await
            .expect("poison row");
    assert_eq!(
        status, "failed",
        "the unmappable row must be resolved terminally, not stranded in 'running'",
    );
    assert!(
        last_error.unwrap_or_default().contains("artifact_id"),
        "the terminal row must carry the projection error for the operator",
    );

    // Nothing is left in the un-reclaimable limbo the old code produced.
    assert_eq!(
        count_where(&pool, "status = 'running' AND kind = 'provenance-verify'").await,
        3,
        "the three healthy rows are running because they were handed to the caller",
    );

    // The claim keeps working on subsequent ticks — no repeated poisoning.
    let next = repo
        .claim_pending_by_kinds(&kinds, REAL_BATCH_SIZE, "w", Duration::from_secs(900))
        .await
        .expect("subsequent claims are unaffected");
    assert_eq!(next.len(), 4);
}

// ---------------------------------------------------------------------------
// F1 property — the audit query mirrors the claim's eligibility predicate
// ---------------------------------------------------------------------------

/// `eligible_pending_by_kind` must count exactly the rows the claim query
/// considers claimable (minus its kind filter): `status = 'pending'` and
/// the lock free or expired. If it drifted from that, the starvation
/// audit would either miss a real backlog or alarm on rows the claim
/// never wanted.
#[tokio::test]
#[serial(hort_pg_db)]
async fn eligible_pending_by_kind_mirrors_the_claim_eligibility_predicate() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    seed_provenance(&pool, 3, 0, 60).await;
    // Not eligible: already running.
    sqlx::query(
        "INSERT INTO public.jobs (kind, params, priority, trigger_source, status) \
         VALUES ('provenance-verify', '{}'::jsonb, 0, 'ingest', 'running')",
    )
    .execute(&pool)
    .await
    .expect("seed running row");
    // Not eligible: pending but lock still held.
    sqlx::query(
        "INSERT INTO public.jobs (kind, params, priority, trigger_source, status, locked_until) \
         VALUES ('provenance-verify', '{}'::jsonb, 0, 'ingest', 'pending', \
         now() + interval '10 minutes')",
    )
    .execute(&pool)
    .await
    .expect("seed locked row");
    // Eligible: pending with an EXPIRED lock — the claim takes these.
    sqlx::query(
        "INSERT INTO public.jobs (kind, params, priority, trigger_source, status, locked_until) \
         VALUES ('noop', '{}'::jsonb, 0, 'manual', 'pending', now() - interval '1 minute')",
    )
    .execute(&pool)
    .await
    .expect("seed expired-lock row");

    let backlog = repo
        .eligible_pending_by_kind()
        .await
        .expect("eligible_pending_by_kind");

    let prov = backlog
        .iter()
        .find(|b| b.kind == "provenance-verify")
        .expect("provenance backlog");
    assert_eq!(
        prov.count, 3,
        "running and still-locked rows are not claim-eligible: {backlog:?}"
    );
    let noop = backlog
        .iter()
        .find(|b| b.kind == "noop")
        .expect("noop backlog");
    assert_eq!(
        noop.count, 1,
        "a pending row whose lock has EXPIRED is claim-eligible"
    );
}

// ---------------------------------------------------------------------------
// F2 — reserved-oldest-slot fairness bounds the starvation window
// ---------------------------------------------------------------------------

/// The exact shape the priority race would otherwise reproduce forever: an
/// old, low-priority backlog of a kind sitting behind a SUSTAINED stream of
/// fresh high-priority rows of the SAME kind. Before the reserved-oldest
/// slot, `ORDER BY priority DESC, created_at ASC LIMIT batch_size` never
/// reaches the old rows as long as the fresh stream keeps saturating every
/// slot — an unbounded stall. One claim slot per poll is now reserved for
/// the single globally oldest eligible row across the claimed kinds,
/// regardless of priority, so as long as the old rows remain older than
/// every freshly-inserted row (true here: the fresh stream is inserted with
/// `age_secs = 0` on every iteration), each poll claims at least one of
/// them. The bound is exact — one old row per poll — not a generous
/// estimate, so a regression back to unbounded starvation fails this test
/// well before any timeout would.
#[tokio::test]
#[serial(hort_pg_db)]
async fn reserved_oldest_slot_drains_an_old_backlog_under_a_sustained_high_priority_stream() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    const OLD_ROWS: usize = 12;
    // Comfortably more than `BATCH_SIZE - 1`, so the priority-ordered
    // slots are saturated by the fresh stream on every single poll and
    // never spill over into the old backlog on their own.
    const FRESH_PER_POLL: usize = 8;
    const BATCH_SIZE: u16 = REAL_BATCH_SIZE;
    const MAX_POLLS: usize = OLD_ROWS;

    seed_provenance(&pool, OLD_ROWS, 0, 7200).await;

    let kinds = ["provenance-verify"];
    const REMAINING_OLD_PREDICATE: &str =
        "kind = 'provenance-verify' AND priority = 0 AND status = 'pending'";

    let mut polls_used = 0;
    for poll in 1..=MAX_POLLS {
        seed_provenance(&pool, FRESH_PER_POLL, 10, 0).await;
        repo.claim_pending_by_kinds(&kinds, BATCH_SIZE, "w", Duration::from_secs(900))
            .await
            .expect("claim");
        polls_used = poll;
        if count_where(&pool, REMAINING_OLD_PREDICATE).await == 0 {
            break;
        }
    }

    assert_eq!(
        count_where(&pool, REMAINING_OLD_PREDICATE).await,
        0,
        "the old prio-0 backlog must fully drain within {MAX_POLLS} polls under a sustained \
         prio-10 stream of the same kind ({polls_used} polls actually used)",
    );
    assert!(
        polls_used <= MAX_POLLS,
        "drain took {polls_used} polls, exceeding the hard bound of {MAX_POLLS}",
    );
}
