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
//! [`older_same_priority_backlog_out_sorts_a_newer_sweep_row`]: at the
//! time of the observation the S4 re-enqueue priority EQUALLED the
//! scheduled-sweep priority (both `10`), and the provenance rows are the
//! older ones, so a priority/`LIMIT` race would starve the SWEEP, not the
//! verifies — the inverse of what was observed.
//!
//! **That equality is history.** The ordinal is now derived from the
//! class (`hort_domain::types::task_tier`), the release sweep is
//! client-waited whatever triggers it, and the two numbers are no longer
//! the same — see [`OBSERVED_ORDINAL`] and
//! [`the_observed_ordinal_is_no_longer_what_the_table_answers`]. The
//! reproductions below carry the observed numbers because that is what
//! reproducing a past state means; the ranking the system writes *now*
//! is asserted separately by
//! [`a_fresh_client_waited_row_is_claimed_over_an_older_bulk_backlog`]
//! and
//! [`a_backlog_at_the_previous_schemes_ordinal_does_not_outrank_a_fresh_sweep`].
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
use hort_adapters_postgres::permission_grant_repo::PgPermissionGrantRepository;
use hort_adapters_postgres::user_repo::PgUserRepository;
use hort_app::destructive_task_reauthorization::DestructiveTaskReauthorizer;
use hort_app::task_dispatcher::TaskDispatcher;
use hort_domain::error::DomainResult;
use hort_domain::policy::DEFAULT_CLASS_SERVICE_THRESHOLD_SECS;
use hort_domain::ports::jobs_repository::ClaimReservation;
use hort_domain::ports::jobs_repository::{JobsRepository, TriggerSource};
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;
use hort_domain::types::task_tier::{
    queue_priority, scan_queue_priority, DEFAULT_RESERVED_SLOTS_PER_CLASS,
};

/// `deploy/compose/docker-compose.yml` — `HORT_SCANNER_BATCH_SIZE`.
const REAL_BATCH_SIZE: u16 = 4;
// A batch of one is entirely the per-class reservation's first slot, so
// nothing is left for the ranked remainder — and
// `a_fresh_client_waited_row_is_claimed_over_an_older_bulk_backlog`
// would then pass without the backlog ever competing, which is the half
// of it that proves the ranking does anything. (Before the reservation
// landed the same assertion was needed for the opposite reason: the one
// slot was the priority-blind oldest row's, which no ordinal can reach.
// `at_a_batch_of_one_the_class_reservation_outranks_the_age_slot` is
// where that size is now asserted on purpose.)
const _: () = assert!(REAL_BATCH_SIZE > 1);
/// `HORT_SCANNER_MAX_ATTEMPTS`'s default — the attempt budget the
/// dispatcher closes rows out against. Irrelevant to the claim
/// starvation these tests reproduce (no row here reaches an outcome
/// write), but the constructor takes the operator's number rather than
/// supplying one, so the test states which number it is standing in
/// for.
const REAL_MAX_ATTEMPTS: u32 = 6;
/// The ordinal every row in the observed jobs-table dump carried — the
/// S4 expiry-backstop re-enqueue and the scheduled sweep beside it, the
/// same number on both sides. That identity is what rules the priority
/// race out as the cause, so the reproductions below seed it on both
/// sides deliberately.
///
/// **Written down here as local history, not read off the ordinal
/// table.** It was read off the table while the numbers had not moved;
/// they have now (the sweep is client-waited whatever triggers it, and
/// the ordinal follows the class), so a read would silently stop
/// reproducing the observation instead of failing. A reproduction of a
/// past state carries the past numbers.
///
/// What keeps the substitution honest is
/// [`the_observed_ordinal_is_no_longer_what_the_table_answers`], which
/// asserts the divergence rather than leaving it implied.
const OBSERVED_ORDINAL: i16 = 10;

/// The reservation a production worker polls with — the same one
/// `hort_adapters_postgres::test_support::claim_reservation` hands the
/// sibling suites, re-exposed locally so the tests that are *about* the
/// reservation and the tests that merely inherit it read the same call.
fn reservation() -> ClaimReservation {
    hort_adapters_postgres::test_support::claim_reservation()
}

async fn isolated_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    hort_adapters_postgres::test_support::isolated_db_from(&url).await
}

async fn seed_provenance(pool: &PgPool, n: usize, priority: i16, age_secs: i64) {
    for _ in 0..n {
        // Mirrors `enqueue_provenance_verify_in_tx` / the S4
        // `enqueue_task("provenance-verify", …)` row shape. The trigger
        // source is `'ingest'` because that is what the ~1450 observed
        // rows carried: both the ingest-time and the clearance-gating
        // verify stamped it then, which is the indistinguishability the
        // `'clearance'` literal later removed. These tests reproduce the
        // rows as observed, and the kind — not the trigger source — is
        // the premise they turn on.
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
    seed_provenance(&pool, 200, OBSERVED_ORDINAL, 600).await;

    let sweep_runs = Arc::new(AtomicUsize::new(0));
    let mut dispatcher = TaskDispatcher::new(
        jobs.clone(),
        publisher,
        // Required by the constructor so no worker dispatches
        // destructive work without a live authority re-check. This test
        // registers only non-destructive kinds, so it is never
        // consulted — the real adapters keep that honest rather than a
        // stub that would stop resembling production.
        Arc::new(DestructiveTaskReauthorizer::new(
            Arc::new(PgUserRepository::new(pool.clone())),
            Arc::new(PgPermissionGrantRepository::new(pool.clone())),
        )),
        "hort-worker-v2",
        Duration::from_secs(900),
        0, // poll as fast as the test can drive it
        REAL_BATCH_SIZE,
        REAL_MAX_ATTEMPTS,
        DEFAULT_RESERVED_SLOTS_PER_CLASS,
        // The per-class service threshold (ADR 0066 D5). Irrelevant to
        // what these tests assert — no verdict is read back — but the
        // constructor takes the operator's number rather than supplying
        // one, so the test states which number it stands in for.
        Duration::from_secs(DEFAULT_CLASS_SERVICE_THRESHOLD_SECS),
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
            OBSERVED_ORDINAL,
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
/// and cron priorities equal — [`OBSERVED_ORDINAL`] on both sides, as
/// observed — resolves on `created_at`, and the verify backlog is the
/// older side. A priority/`LIMIT` starvation would therefore hold back
/// the newly-enqueued sweep row — the inverse of the reported incident.
/// Pinned so the candidate is not re-litigated.
///
/// The equal ordinal is seeded, not asked for: the system no longer
/// writes those two rows at the same rank, which is what
/// [`a_fresh_client_waited_row_is_claimed_over_an_older_bulk_backlog`]
/// asserts.
#[tokio::test]
#[serial(hort_pg_db)]
async fn older_same_priority_backlog_out_sorts_a_newer_sweep_row() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let repo = PgJobsRepository::new(pool.clone());

    seed_provenance(&pool, 60, OBSERVED_ORDINAL, 600).await;
    let sweep: Uuid = sqlx::query_scalar(
        "INSERT INTO public.jobs (kind, params, priority, trigger_source, status) \
         VALUES ('quarantine-release-sweep', '{}'::jsonb, $1, 'cron', 'pending') RETURNING id",
    )
    .bind(OBSERVED_ORDINAL)
    .fetch_one(&pool)
    .await
    .expect("seed sweep row");

    let kinds = ["provenance-verify", "quarantine-release-sweep"];
    for _ in 0..5 {
        let rows = repo
            .claim_pending_by_kinds(
                &kinds,
                REAL_BATCH_SIZE,
                "w",
                Duration::from_secs(900),
                &reservation(),
            )
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
/// The shape used to be production-reachable: `"scan"` was in
/// `ADMIN_INVOKABLE_TASK_KINDS`, so the admin task-invoke path's `enqueue_task`
/// wrote a `kind='scan'` row with the scan-typed columns NULL, which
/// `decide_kind_fields` rejects. That source is now closed at the apply
/// side (no admin route, and the kind is off the allow-list), but the
/// `jobs` table still has no CHECK preventing the shape — a row seeded
/// by direct SQL, left over from an older deployment, or produced by a
/// future kind whose typed columns go missing must still not take its
/// whole claimed batch down. This is that defence-in-depth proof, and
/// the seed below is deliberately raw SQL for exactly that reason.
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
    .bind(OBSERVED_ORDINAL)
    .fetch_one(&pool)
    .await
    .expect("seed poison scan row");
    seed_provenance(&pool, 8, OBSERVED_ORDINAL, 1800).await;

    let kinds = ["scan", "provenance-verify"];
    let claimed = repo
        .claim_pending_by_kinds(
            &kinds,
            REAL_BATCH_SIZE,
            "w",
            Duration::from_secs(900),
            &reservation(),
        )
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
        .claim_pending_by_kinds(
            &kinds,
            REAL_BATCH_SIZE,
            "w",
            Duration::from_secs(900),
            &reservation(),
        )
        .await
        .expect("subsequent claims are unaffected");
    assert_eq!(next.len(), 4);
}

// ---------------------------------------------------------------------------
// Non-displacement at the claim (ADR 0066 D4, point one)
// ---------------------------------------------------------------------------

/// Seed `n` `kind='scan'` rows at the ordinal the table answers for
/// `trigger_source`, aged `age_secs`.
///
/// Raw SQL rather than `enqueue_scan` so the age is the test's to
/// choose; the ordinal is **not** the test's — it comes from
/// `scan_queue_priority`, so a re-ranking moves these fixtures with it
/// instead of leaving them standing on a number that used to be true.
/// Every row gets a fresh `artifact_id`, because the partial unique
/// index over non-terminal scan rows admits one per artifact.
async fn seed_scans(pool: &PgPool, n: usize, trigger_source: &str, age_secs: i64) {
    for _ in 0..n {
        sqlx::query(
            "INSERT INTO public.jobs (kind, artifact_id, repository_id, content_hash, format, \
             priority, trigger_source, status, created_at, updated_at) \
             VALUES ('scan', $1, $2, $3, 'npm', $4, $5, 'pending', \
             now() - make_interval(secs => $6), now() - make_interval(secs => $6))",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind("a".repeat(64))
        .bind(scan_queue_priority(trigger_source))
        .bind(trigger_source)
        .bind(age_secs as f64)
        .execute(pool)
        .await
        .expect("seed scan row");
    }
}

/// Claim one batch of `kind='scan'` and report each claimed row's
/// trigger source.
async fn claim_scan_trigger_sources(pool: &PgPool, batch_size: u16) -> Vec<String> {
    PgJobsRepository::new(pool.clone())
        .claim_pending_by_kinds(
            &["scan"],
            batch_size,
            "w",
            Duration::from_secs(900),
            &reservation(),
        )
        .await
        .expect("claim")
        .into_iter()
        .map(|r| r.trigger_source)
        .collect()
}

/// **Point one of ADR 0066 D4.** A flood of one class cannot take the
/// whole batch while another waited-on class has an eligible row.
///
/// The flood here outranks its victim, which is what makes this a
/// *reservation* test rather than a ranking test: the ingest scans are
/// `Interactive` and the operator's rescan is `Normal`, so no ordering
/// of the batch by rank can ever reach the rescan — "ranking decides
/// who wins a comparison; it does not reserve anything". The age slot
/// cannot reach it either: the rescan is the newest row in the table.
/// With a slot held for every non-empty waited-on class, it is claimed
/// in the same batch.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_waited_on_class_keeps_a_slot_against_a_flood_of_a_higher_class() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let interactive = TriggerSource::Ingest.as_str();
    let normal = TriggerSource::Manual.as_str();
    // The premise this test rests on: the flood really does outrank its
    // victim, so a reservation is the only thing that can save it.
    assert!(
        scan_queue_priority(interactive) > scan_queue_priority(normal),
        "the fixture needs the flood to outrank the row it would displace"
    );

    seed_scans(&pool, 60, interactive, 600).await;
    seed_scans(&pool, 1, normal, 0).await;

    let claimed = claim_scan_trigger_sources(&pool, REAL_BATCH_SIZE).await;
    assert!(
        claimed.iter().any(|t| t == normal),
        "the operator's rescan must keep a slot against the ingest flood: {claimed:?}"
    );
    assert!(
        claimed.iter().any(|t| t == interactive),
        "the flood must really be competing for the batch — otherwise the claim above \
         proves nothing: {claimed:?}"
    );
}

/// **The small-batch reconciliation.** At `HORT_SCANNER_BATCH_SIZE = 1`
/// the whole batch is one slot, and the per-class reservation takes it
/// ahead of the priority-blind oldest slot.
///
/// Decided rather than inherited: the age reservation is the mitigation
/// ADR 0066 replaces ("age is the wrong axis to reserve on" — it
/// protects the oldest row, and in the state that matters the oldest row
/// is itself part of the backlog), so letting it keep the only slot
/// would mean the replacement never takes effect at the one batch size
/// where it matters most. Here the bulk backlog is older than the
/// client-waited row by construction, which is exactly the state the age
/// slot resolves the wrong way.
#[tokio::test]
#[serial(hort_pg_db)]
async fn at_a_batch_of_one_the_class_reservation_outranks_the_age_slot() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let bulk = TriggerSource::Cron.as_str();
    let interactive = TriggerSource::Ingest.as_str();

    seed_scans(&pool, 10, bulk, 600).await;
    seed_scans(&pool, 1, interactive, 0).await;

    let claimed = claim_scan_trigger_sources(&pool, 1).await;
    assert_eq!(
        claimed,
        vec![interactive.to_string()],
        "the single slot must go to the client-waited row, not to the oldest row of the \
         backlog it is waiting behind: {claimed:?}"
    );
}

/// The reservation works in a **mixed ordinal space** — a tree that
/// still holds rows an older binary queued — and does not strand them.
///
/// ADR 0066 D7: the classification is derived and needs no backfill, but
/// the *ordinal* is on the row, and the claim's reservation reads the
/// class off the ordinal because the SQL may not learn the
/// classification. So a legacy row's band membership disagrees with its
/// class until it drains: these `provenance-verify` rows are
/// `Interactive` by `classify` and sit in the `Bulk` band at
/// [`OBSERVED_ORDINAL`], which is the ordinal this installation actually
/// had queued.
///
/// Two things have to hold at once, and the second is the risk this
/// change introduces rather than inherits: the fresh client-waited row
/// gets its reserved slot (so a legacy backlog cannot consume it — the
/// disagreement is safe in the direction that matters), and the legacy
/// backlog still drains out of the slots beneath the reservation (so the
/// reservation does not strand the rows it cannot classify).
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_reservation_holds_in_a_mixed_ordinal_space_without_stranding_it() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    const LEGACY_ROWS: usize = 30;
    let sweep_kind = "quarantine-release-sweep";
    let sweep_source = TriggerSource::Cron.as_str();

    seed_provenance(&pool, LEGACY_ROWS, OBSERVED_ORDINAL, 600).await;
    let repo = PgJobsRepository::new(pool.clone());
    repo.enqueue_task(
        sweep_kind,
        &serde_json::json!({}),
        None,
        queue_priority(sweep_kind, sweep_source),
        sweep_source,
        None,
    )
    .await
    .expect("enqueue the release sweep");

    let claimed: Vec<String> = repo
        .claim_pending_by_kinds(
            &["provenance-verify", sweep_kind],
            REAL_BATCH_SIZE,
            "w",
            Duration::from_secs(900),
            &reservation(),
        )
        .await
        .expect("claim")
        .into_iter()
        .map(|r| r.kind)
        .collect();

    assert!(
        claimed.iter().any(|k| k == sweep_kind),
        "the fresh client-waited row must keep its reserved slot beside a backlog an \
         older binary queued at {OBSERVED_ORDINAL}: {claimed:?}"
    );
    assert!(
        claimed.iter().any(|k| k == "provenance-verify"),
        "the legacy backlog must still drain out of the slots beneath the reservation — \
         a reservation that took the whole batch would stall rows it cannot classify: \
         {claimed:?}"
    );
}

/// The age slot survives **beneath** the reservation: it is what
/// guarantees `Bulk` service (ADR 0066 D5), since nobody waits on bulk
/// work and so it gets no reserved share of its own.
///
/// The shape is the reservation's own blind spot — an old row of a
/// flooded class, where the flood is *in the same band*, so no per-class
/// reservation can separate them. Only age can, which is why the age
/// slot is kept rather than replaced: ADR 0066 puts aging "beneath (4),
/// not as a substitute for it".
#[tokio::test]
#[serial(hort_pg_db)]
async fn the_age_slot_still_reaches_an_old_row_of_a_flooded_class() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let bulk = TriggerSource::Cron.as_str();
    // The old row is the one the age slot has to reach: it is the oldest
    // in the table and ranks no higher than the flood around it.
    seed_scans(&pool, 1, bulk, 7200).await;
    let oldest_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM public.jobs WHERE kind = 'scan' ORDER BY created_at ASC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("the old row exists");

    // A flood that saturates every ranked slot, of a class that outranks
    // the old row's and is newer than it.
    seed_scans(&pool, 60, TriggerSource::Ingest.as_str(), 0).await;

    let claimed: Vec<Uuid> = PgJobsRepository::new(pool.clone())
        .claim_pending_by_kinds(
            &["scan"],
            REAL_BATCH_SIZE,
            "w",
            Duration::from_secs(900),
            &reservation(),
        )
        .await
        .expect("claim")
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert!(
        claimed.contains(&oldest_id),
        "the priority-blind oldest slot must still reach the oldest eligible row — it is \
         the only guarantee of service a class with no reserved share has: {claimed:?}"
    );
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
        repo.claim_pending_by_kinds(
            &kinds,
            BATCH_SIZE,
            "w",
            Duration::from_secs(900),
            &reservation(),
        )
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

// ---------------------------------------------------------------------------
// The re-ranking, proved at the SQL level
// ---------------------------------------------------------------------------

/// Seed a flood of older `Bulk` rows at `backlog_priority`, enqueue one
/// quarantine-release sweep newer than every one of them through the real
/// adapter, claim a single batch, and report the kinds the claim took.
///
/// The flood is `kind = 'scan'` with `trigger_source = 'cron'` — the
/// scheduled rescan tick's own row shape, which is the flood the reported
/// stall was behind. Seeded by raw SQL rather than `enqueue_scan` so the
/// ordinal and the age are the test's to choose; every row gets a fresh
/// `artifact_id`, because the partial unique index over non-terminal scan
/// rows admits one per artifact.
async fn claim_over_a_cron_rescan_backlog(pool: &PgPool, backlog_priority: i16) -> Vec<String> {
    const BACKLOG: usize = 60;
    for _ in 0..BACKLOG {
        sqlx::query(
            "INSERT INTO public.jobs (kind, artifact_id, repository_id, content_hash, format, \
             priority, trigger_source, status, created_at, updated_at) \
             VALUES ('scan', $1, $2, $3, 'npm', $4, 'cron', 'pending', \
             now() - interval '10 minutes', now() - interval '10 minutes')",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind("a".repeat(64))
        .bind(backlog_priority)
        .execute(pool)
        .await
        .expect("seed cron rescan backlog row");
    }

    let repo = PgJobsRepository::new(pool.clone());
    let sweep_kind = "quarantine-release-sweep";
    let sweep_source = TriggerSource::Cron.as_str();
    repo.enqueue_task(
        sweep_kind,
        &serde_json::json!({}),
        None,
        queue_priority(sweep_kind, sweep_source),
        sweep_source,
        None,
    )
    .await
    .expect("enqueue the release sweep");

    repo.claim_pending_by_kinds(
        &["scan", sweep_kind],
        REAL_BATCH_SIZE,
        "w",
        Duration::from_secs(900),
        &reservation(),
    )
    .await
    .expect("claim")
    .into_iter()
    .map(|r| r.kind)
    .collect()
}

/// **The reported stall's shape, at the SQL level.** A backlog of bulk
/// rows pending, one client-waited row newer than all of them, and the
/// client-waited row is claimed.
///
/// This is the test the issue exists for. It is *not* non-displacement —
/// the flood still occupies the rest of the batch, and the per-class
/// reservation that fixes that is its own change (ADR 0066 D4). It holds
/// here because the ordinal finally says the right thing: the release
/// sweep is client-waited whatever triggers it, so it outranks the
/// scheduled rescans that share its `'cron'` trigger source instead of
/// tying with them and losing the age tiebreak.
///
/// One batch slot is the claim's reserved-oldest slot, which goes to the
/// globally oldest eligible row regardless of rank — so the sweep is
/// claimed out of the *ranked* remainder, and this test needs
/// `REAL_BATCH_SIZE > 1` to say anything. At a batch size of one the
/// reserved slot is the whole batch and no ordinal can help, which is a
/// property of the claim rather than of the ranking.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_fresh_client_waited_row_is_claimed_over_an_older_bulk_backlog() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let sweep_kind = "quarantine-release-sweep";
    let claimed =
        claim_over_a_cron_rescan_backlog(&pool, scan_queue_priority(TriggerSource::Cron.as_str()))
            .await;
    assert!(
        claimed.iter().any(|k| k == sweep_kind),
        "the newest client-waited row must be claimed over the older bulk backlog: {claimed:?}"
    );
    assert!(
        claimed.iter().any(|k| k == "scan"),
        "the backlog must really be competing for the batch — otherwise the claim above \
         proves nothing: {claimed:?}"
    );
}

/// Counter-assertion for the test above: the claim really does order by
/// the ordinal, so a backlog ranked *above* the sweep buries it.
///
/// Without this, a claim query that had stopped reading `priority`
/// altogether would pass the acceptance test by accident — the sweep is
/// one of only two kinds in the array and would turn up in a batch of
/// four whatever the ordering said.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_backlog_ranked_above_the_sweep_does_bury_it() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let sweep_kind = "quarantine-release-sweep";
    let above = queue_priority(sweep_kind, TriggerSource::Cron.as_str()) + 1;
    let claimed = claim_over_a_cron_rescan_backlog(&pool, above).await;
    assert!(
        !claimed.iter().any(|k| k == sweep_kind),
        "a backlog at {above}, above the sweep's own ordinal, must take every ranked slot: \
         {claimed:?}"
    );
}

/// **The upgrade property, at the SQL level.** A backlog carrying the
/// ordinal the *previous* scheme wrote — [`OBSERVED_ORDINAL`], which is
/// what the rows in the observed dump carried — does not outrank a
/// release sweep a current binary enqueues.
///
/// This is the mixed-fleet case: the classification is derived and needs
/// no backfill (ADR 0066 D7), but the ordinal is on the row, so the bands
/// have to be chosen such that rows an older binary already queued drain
/// without displacing anything. The previous scheme's highest number was
/// `20` and every band above `Bulk` is above it, which is why no
/// migration is needed; `OBSERVED_ORDINAL` is the number this
/// installation actually had queued.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_backlog_at_the_previous_schemes_ordinal_does_not_outrank_a_fresh_sweep() {
    let Some(pool) = isolated_pool().await else {
        return;
    };
    let sweep_kind = "quarantine-release-sweep";
    let claimed = claim_over_a_cron_rescan_backlog(&pool, OBSERVED_ORDINAL).await;
    assert!(
        claimed.iter().any(|k| k == sweep_kind),
        "a fresh release sweep must outrank a backlog an older binary queued at \
         {OBSERVED_ORDINAL}: {claimed:?}"
    );
}

/// The equality the reproductions above stand on is **historical**: the
/// ordinal table no longer answers [`OBSERVED_ORDINAL`] for either side,
/// and no longer answers the same number for both.
///
/// DB-free, and deliberately in this file rather than beside the band
/// arithmetic: it is what stops the seeded `OBSERVED_ORDINAL` from
/// quietly becoming "whatever the table says" again, and it states the
/// upgrade property against the one ordinal this installation is known to
/// have had queued.
#[test]
fn the_observed_ordinal_is_no_longer_what_the_table_answers() {
    let sweep = queue_priority("quarantine-release-sweep", TriggerSource::Cron.as_str());
    let clearance = queue_priority("provenance-verify", TriggerSource::Clearance.as_str());
    let ingest_verify = queue_priority("provenance-verify", TriggerSource::Ingest.as_str());

    assert_ne!(
        sweep, clearance,
        "the two ordinals were equal when the stall was observed, which is what ruled the \
         priority race out as its cause; if they are equal again the ranking has been \
         flattened and the reasoning in this file's header has to be redone"
    );
    for (label, fresh) in [
        ("the release sweep", sweep),
        ("the clearance verify", clearance),
        ("the ingest-time verify", ingest_verify),
    ] {
        assert!(
            fresh > OBSERVED_ORDINAL,
            "{label} must outrank a row an older binary queued at {OBSERVED_ORDINAL}, or the \
             re-ranking would need a backfill — it answered {fresh}"
        );
    }
}
