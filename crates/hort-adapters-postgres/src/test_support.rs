//! Test-only support: **per-test database isolation**.
//!
//! `#[doc(hidden)]` — not part of the public API; compiled always so
//! that `hort-adapters-postgres`'s own `#[cfg(test)]` modules, its
//! `tests/` integration binaries, and the `hort-server` integration
//! tests can all share one isolation helper without a feature-flag
//! dance.
//!
//! ## Why
//!
//! The DB-backed test suites historically connected to ONE shared
//! database and each ran `sqlx::migrate!().run()` against it. Cargo
//! runs the test binaries one after another, but libtest runs the tests
//! *within* a binary on many threads at once, and each binary in turn
//! inherited every earlier binary's leftovers — so they raced and
//! corrupted each other's schema/data (concurrent migrate,
//! `DROP TABLE … CASCADE` collateral, before/after deltas on global
//! streams, …). [`isolated_db_from`] gives every caller its own
//! freshly-created database, so cross-test/cross-binary interference is
//! structurally impossible. The caller still runs its own
//! `sqlx::migrate!().run()` on the returned pool (kept at the call site
//! so the embedded-migration set stays crate-local; the workspace
//! `build.rs` files make that embed track `migrations`).
//!
//! ## Cleanup — a once-per-process sweep (issue #37)
//!
//! A throwaway database is still not dropped at the end of its own
//! test (there is no teardown hook — [`isolated_db_from`] hands back a
//! bare `PgPool`). Instead each test **process** sweeps stale ones
//! once, before creating its own.
//!
//! This reverses an earlier decision. That comment read: *"intentionally
//! not dropped … locally it is harmless clutter, removed by recreating
//! the dev DB."* Both premises expired once the dev environment became
//! fully automated: nobody recreates the dev DB by hand, so the
//! databases accumulated monotonically — **1,091 of them, 11 GB**, at
//! which point every unclean postgres restart replayed a ~2.5-minute
//! recovery (64k files fsynced, 715 MB of WAL) and every connection
//! attempt inside that window failed with `57P03` / `PoolTimedOut`.
//! That was the whole of issue #37's "flakiness".
//!
//! The sweep is safe by construction, not by luck:
//!
//! - the database name carries its creation time
//!   (`hort_test_<unix_secs>_<uuid>`), and only entries older than
//!   [`STALE_AFTER_SECS`] are considered — so a database another
//!   process created moments ago is never a candidate, even mid-sweep;
//! - candidates with any live connection in `pg_stat_activity` are
//!   skipped, so a long-running concurrent test is doubly protected;
//! - every step is best-effort: any error is ignored and the caller
//!   proceeds to create its own database. Cleanup must never be the
//!   reason a test fails.
//!
//! It does not *prevent* a leak — a drop-on-teardown guard would, at the
//! cost of a guard type threaded through the 59 files that call
//! [`isolated_db_from`] and a database drop issued from a synchronous
//! `Drop`. Deliberately not done.
//!
//! ## The sweep is bounded in wall clock, not in candidates
//!
//! The sweep's cost falls on the run it belongs to rather than on the
//! sibling it is trying not to disturb. Every `DROP DATABASE` makes the
//! backend request an immediate, waited-on checkpoint — visible as
//! `IPC/CheckpointStart` then `IPC/CheckpointDone` in
//! `pg_stat_activity.wait_event`, and as `checkpoints_req` rising by
//! exactly +1251 across 1251 drops — so a sweep is a serial queue of
//! forced checkpoints, one per candidate, issued from inside the first
//! DB-backed test of the process, which holds the crate-wide
//! `#[serial(hort_pg_db)]` key for the whole of it. Measured: 60–80 ms
//! per drop against an otherwise idle server, so 1,251 candidates became
//! a 77-second stall that pushed three unrelated tests past libtest's
//! 60-second slow-test threshold. And the per-drop cost is bounded by
//! nothing the harness controls: a single `DROP DATABASE` was observed
//! waiting 136 seconds for its checkpoint while a second process ran
//! migration sets, and 73 seconds on `Lock/object` when two test
//! processes swept the same candidate list at once (each
//! `DROP DATABASE` takes an exclusive lock on the database object, so
//! concurrent sweeps serialise against each other).
//!
//! A cap on the *number* of drops therefore bounds the wrong quantity:
//! at the worst measured per-drop cost, fifty drops is over an hour with
//! the serial key held throughout. Three bounds instead, each on
//! something it can actually hold:
//!
//! - [`SWEEP_BUDGET`] — wall clock across the whole drop loop, checked
//!   between drops.
//! - [`DROP_STATEMENT_TIMEOUT_MS`] — server-side ceiling on one
//!   `DROP DATABASE`. This is what closes the one drop the budget cannot
//!   interrupt.
//! - [`DROP_LOCK_TIMEOUT_MS`] — server-side ceiling on the object-lock
//!   wait alone. A candidate whose lock is held is one a concurrent
//!   sweeper is already dropping, so waiting on it spends this sweep's
//!   budget on work that is being done anyway.
//!
//! Candidates are taken in random order for the same reason: sweeps that
//! walk one stable order meet on the same first candidates, which is the
//! `Lock/object` measurement above. Re-dropping a candidate a peer
//! already removed is free (`DROP DATABASE IF EXISTS` on an absent name
//! returns in under a millisecond — no checkpoint), so overlap costs
//! nothing beyond the lock wait that [`DROP_LOCK_TIMEOUT_MS`] bounds.
//!
//! ### What the bound guarantees
//!
//! One sweep holds `#[serial(hort_pg_db)]` for at most [`SWEEP_BUDGET`]
//! plus [`DROP_STATEMENT_TIMEOUT_MS`]. Both halves are verified rather
//! than assumed: the loop's budget by this module's DB-free tests
//! against an artificially slowed drop, and the statement timeout
//! against a real server — a `DROP DATABASE` parked on
//! `IPC/CheckpointStart`/`IPC/CheckpointDone` is cancelled at exactly
//! the configured deadline with SQLSTATE 57014. A checkpoint wait is not
//! a lock wait, so that one had to be measured.
//!
//! Interrupting a `DROP DATABASE` is *safe*, not merely tolerated, and
//! that is a property of the server version: PostgreSQL 16 commits an
//! "invalid database" marker (`pg_database.datconnlimit = -2`) before
//! the destructive phase, so a cancelled drop leaves a database that
//! cannot be connected to, is still matched by the candidate query, and
//! is finished by the next sweep in tens of milliseconds. Both CI
//! pipelines and the sandbox run PostgreSQL 16; on an older server an
//! interrupted drop carries no such guarantee, and
//! [`DROP_STATEMENT_TIMEOUT_MS`] would have to be re-justified there.
//!
//! ### What the bound does not guarantee
//!
//! It does not bound the *population*. A budget bounds what one sweep
//! costs, not how many databases exist: if `CREATE DATABASE` outruns the
//! aggregate drain rate across a run's sweeping processes, the
//! population still climbs. The only thing that says so is the
//! budget-exhausted line [`report_sweep`] writes to stderr.
//!
//! It does not make the cluster safe. The crash this bound sits next to
//! was `/dev/shm` exhaustion — 60 of 63 MB at 634 test databases, against
//! a single dynamic-shared-memory segment request of 32 MB — and the
//! 63 MB ceiling is a container `--shm-size`, outside this repository.
//! Measured the same morning, the baseline is 44 MB with *zero* test
//! databases: the population is the multiplier, not the cause, and
//! shrinking it is not a substitute for raising the ceiling.
//!
//! It does not bound anything else [`isolated_db_from`] does. `CREATE
//! DATABASE` and the migration set that follows it run with no timeout,
//! deliberately: cancelling either one fails the test that asked for the
//! database, which is the opposite of the best-effort contract the sweep
//! holds itself to.
//!
//! ## Pool sizing is deliberately left at sqlx's defaults
//!
//! A `PoolTimedOut` from a DB-backed test invites capping
//! `max_connections` on these pools. Measurement refutes that reading
//! twice over, so the defaults stay. Sampling `pg_stat_activity` once a
//! second through a whole `cargo test --workspace` (1,072 samples)
//! peaked at **11 concurrent client backends against 97 usable**
//! (`max_connections` 100 less 3 reserved — and one of the 11 was the
//! sampler itself), sat at 2 for 69% of them, and never had more than 3
//! test databases connected at once: sqlx pools are lazy
//! (`min_connections = 0`) and cargo runs test binaries one at a time,
//! so they never approach the server's limit. And a second
//! process's full acquisition path — connect, `CREATE DATABASE`, build
//! the pool, `acquire`, run the whole migration set — showed no
//! degradation at all across a 242-second sweep of 600 databases: every
//! one of its 90 `acquire` calls returned in under a millisecond. A
//! timeout here is not a connection budget that is full, so a smaller
//! pool would change nothing.

use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::time::Duration;
// `tokio::time::Instant` rather than `std::time::Instant` so
// `tokio::test(start_paused = true)` can drive the budget loop through
// virtual time; outside a paused runtime the two behave identically.
use tokio::time::Instant;

/// Age below which a stray `hort_test_*` database is left alone.
///
/// The age gate only has to cover the window between `CREATE DATABASE` and
/// the creating process's first connection appearing in `pg_stat_activity`
/// — milliseconds. After that the live-connection check is the stronger
/// test, and it holds for as long as the owning pool keeps a connection:
/// sqlx reaps an idle one after ten minutes, so ten minutes here means a
/// database is exposed only once its owner has gone that long without
/// touching it *and* is still running — an order of magnitude past
/// libtest's 60-second slow-test threshold.
///
/// One hour was the reason nothing ever came back. It exceeds the interval
/// between consecutive runs during active development, so a run reclaimed
/// neither its own databases nor, usually, its predecessor's, and the
/// population climbed monotonically: four `cargo test --workspace` runs
/// against a cluster reset to zero left **1,251 databases / 11 GB**
/// standing, where one run creates **429**. Ten minutes makes a run's own
/// early databases reclaimable by its own later processes — which is only
/// safe because [`SWEEP_BUDGET`] already bounds what the larger candidate
/// list costs.
const STALE_AFTER_SECS: u64 = 600;

/// Wall-clock ceiling on one sweep's drop loop, and so on the extra time
/// the first DB-backed test of a process holds `#[serial(hort_pg_db)]`.
///
/// Derived, not picked. 36 processes per `cargo test --workspace` reach the
/// sweep (34 integration-test binaries plus the `hort-adapters-postgres` and
/// `hort-server` lib unittest binaries), and a run creates ~437 databases, so
/// the steady state needs 437 / 36 ≈ 12 drops per sweep.
///
/// The per-drop cost that sizes this is **not** the 60–80 ms an idle server
/// gives. Measured across two whole workspace runs — 36 sweeps each, every
/// one of them spending its full budget — the in-run cost was 167 ms and
/// 200 ms per drop: a run saturates the server with its own `CREATE
/// DATABASE` and migration sets, and the sweep's forced checkpoints queue
/// behind that. Twelve drops is therefore ~2.4 s of work, not ~1 s.
///
/// Five seconds is a little over twice the steady-state requirement
/// (36 × 5 s / 200 ms ≈ 900 drops per run against ~437 created), and leaves
/// the worst-case hold — budget plus [`DROP_STATEMENT_TIMEOUT_MS`] — at
/// 6.5 s, an order of magnitude under libtest's 60-second slow-test
/// threshold. Sizing it against the idle cost instead gives 3 s, which
/// measured out at only 1.14–1.39× the creation rate: a drain that slow
/// leaves the population converging over many runs instead of settling.
const SWEEP_BUDGET: Duration = Duration::from_secs(5);

/// Server-side ceiling on a single `DROP DATABASE`, in milliseconds.
///
/// The budget is checked between drops and so cannot interrupt one in
/// flight; this is the bound that can. 1.5 s is ~18× the idle per-drop
/// cost and ~2.5× the cost measured with a concurrent writer and a
/// competing manual `CHECKPOINT`, so it does not fire on a healthy
/// server — and when it does fire the candidate is simply skipped, which
/// is the path every other failure in this sweep already takes.
const DROP_STATEMENT_TIMEOUT_MS: u64 = 1_500;

/// Server-side ceiling on the object-lock wait inside a single
/// `DROP DATABASE`, in milliseconds.
///
/// Subsumed by [`DROP_STATEMENT_TIMEOUT_MS`] as a safety bound, but it
/// buys something that one does not: a contended candidate is one a
/// concurrent sweeper is already dropping, so yielding after a quarter
/// of a second leaves the budget for candidates nobody else is taking.
const DROP_LOCK_TIMEOUT_MS: u64 = 250;

/// The relationship the three bounds above exist to hold: a sweep adds at
/// most the budget plus the one drop the budget cannot interrupt to the time
/// the serial key is held, and libtest calls a test slow at 60 seconds. A
/// compile error rather than a test, because the only way to break it is to
/// edit a constant.
const _: () = assert!(
    SWEEP_BUDGET.as_millis() as u64 + DROP_STATEMENT_TIMEOUT_MS <= 7_000,
    "worst-case sweep hold must stay an order of magnitude under libtest's 60s slow threshold"
);
/// A contended candidate is one a peer sweeper is already dropping, so it
/// must be abandoned sooner than one this sweep is making progress on.
const _: () = assert!(DROP_LOCK_TIMEOUT_MS < DROP_STATEMENT_TIMEOUT_MS);

/// Ensures the stale-database sweep runs at most once per process.
static SWEPT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The one operation the budgeted sweep loop performs per candidate.
///
/// Factored out of [`sweep_stale_databases`] so [`drop_within_budget`] and
/// its clock can be exercised against an artificially slow drop with no
/// server in reach. That seam is not a convenience: the DB-gated suites are
/// main/release-scoped, so a bound tested only through a real (and fast)
/// `DROP DATABASE` would be unverified on the very pipeline that reviews a
/// change to it.
trait DropCandidate {
    /// Returns `true` when the candidate is gone afterwards.
    async fn drop_candidate(&mut self, name: &str) -> bool;
}

/// [`DropCandidate`] backed by the real maintenance connection.
struct SqlDrop<'a>(&'a mut PgConnection);

impl DropCandidate for SqlDrop<'_> {
    async fn drop_candidate(&mut self, name: &str) -> bool {
        // DROP DATABASE cannot run in a transaction; a concurrent
        // connection arriving between the query and here makes this
        // fail, which is exactly the outcome we want — skip it. Same for
        // the server-side timeouts set on this connection: a timed-out
        // drop is the existing skip path with a clock on it.
        self.0
            .execute(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS \"{name}\""
            )))
            .await
            .is_ok()
    }
}

/// What one budgeted drop loop did.
#[derive(Debug, Default, PartialEq, Eq)]
struct SweepOutcome {
    /// Everything the candidate query returned.
    candidates: usize,
    /// Candidates a drop was actually issued for.
    attempted: usize,
    /// Candidates that were gone afterwards.
    dropped: usize,
    /// True when the loop stopped on the clock rather than on the end of
    /// the candidate list — i.e. the population is outrunning the sweep.
    exhausted_budget: bool,
}

/// Drop `names` one at a time until the list is done or `budget` is spent.
///
/// The clock is checked *between* drops, so the loop returns at `budget`
/// plus at most one drop — it cannot interrupt a drop already in flight.
/// That tail is bounded server-side instead, by
/// [`DROP_STATEMENT_TIMEOUT_MS`]; without it the tail is whatever one
/// `DROP DATABASE` costs, which is unbounded.
async fn drop_within_budget<D: DropCandidate>(
    names: Vec<String>,
    budget: Duration,
    dropper: &mut D,
) -> SweepOutcome {
    let started = Instant::now();
    let mut outcome = SweepOutcome {
        candidates: names.len(),
        ..SweepOutcome::default()
    };
    for name in names {
        if started.elapsed() >= budget {
            outcome.exhausted_budget = true;
            break;
        }
        outcome.attempted += 1;
        if dropper.drop_candidate(&name).await {
            outcome.dropped += 1;
        }
    }
    outcome
}

/// The one line a sweep owes a human, or `None` when it owes none.
///
/// A sweep that finished its candidate list is not news, and 36 test
/// processes per workspace run each announcing themselves would train the
/// reader to skip the line. A sweep that ran out of budget is the one state
/// that needs somebody: the population is growing faster than the sweeps
/// drain it, and nothing else in a plain `cargo test` says so.
fn budget_warning(outcome: &SweepOutcome, elapsed: Duration) -> Option<String> {
    if !outcome.exhausted_budget {
        return None;
    }
    Some(format!(
        "hort test-database sweep stopped on its {}s budget after {} ms: {} candidates, \
         {} attempted, {} dropped. Stale `hort_test_*` databases are accumulating faster \
         than the per-process sweep drains them — check the server for slow or contended \
         DROP DATABASE.",
        SWEEP_BUDGET.as_secs(),
        elapsed.as_millis(),
        outcome.candidates,
        outcome.attempted,
        outcome.dropped,
    ))
}

/// Report the sweep where it will actually be read.
///
/// The routine summary stays on `tracing` for whoever reruns with
/// `RUST_LOG=hort_adapters_postgres=debug`; no test binary that reaches this
/// sweep installs a subscriber, so on its own that is a no-op. The warning goes
/// straight to `io::stderr()` rather than through `eprintln!`, because
/// libtest captures the print macros and throws the capture away for a test
/// that passes — which is every test this runs inside.
fn report_sweep(outcome: &SweepOutcome, elapsed: Duration) {
    tracing::debug!(
        candidates = outcome.candidates,
        attempted = outcome.attempted,
        dropped = outcome.dropped,
        exhausted_budget = outcome.exhausted_budget,
        elapsed_ms = elapsed.as_millis(),
        "swept stale test databases"
    );
    if let Some(warning) = budget_warning(outcome, elapsed) {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "{warning}");
    }
}

/// Drop `hort_test_*` databases older than [`STALE_AFTER_SECS`] that
/// have no live connections, for at most [`SWEEP_BUDGET`]. Best-effort:
/// every failure is ignored.
///
/// Runs at most once per process (first [`isolated_db_from`] call).
/// Takes the maintenance connection already opened for `CREATE
/// DATABASE`, so it costs no extra connection.
async fn sweep_stale_databases(admin: &mut PgConnection) {
    use std::sync::atomic::Ordering;
    if SWEPT.swap(true, Ordering::SeqCst) {
        return;
    }

    let cutoff = now_unix_secs().saturating_sub(STALE_AFTER_SECS);

    // `split_part(datname, '_', 3)` is the epoch segment of
    // `hort_test_<epoch>_<uuid>`. Databases predating the timestamped
    // naming have a non-numeric segment there; `~ '^[0-9]+$'` excludes
    // them from the age test, and the second arm sweeps them on the
    // connection check alone (they are, by definition, older).
    //
    // `ORDER BY random()` keeps concurrent sweepers off each other's
    // first candidates: `DROP DATABASE` takes an exclusive lock on the
    // database object, so two sweeps walking one stable order serialise
    // against each other. The whole list is still fetched — its length
    // is the diagnostic the budget warning carries.
    let sql = format!(
        "SELECT d.datname FROM pg_database d \
         LEFT JOIN (SELECT datname, count(*) AS cnt FROM pg_stat_activity GROUP BY datname) a \
           ON a.datname = d.datname \
         WHERE d.datname LIKE 'hort\\_test\\_%' \
           AND COALESCE(a.cnt, 0) = 0 \
           AND (CASE WHEN split_part(d.datname, '_', 3) ~ '^[0-9]+$' \
                     THEN split_part(d.datname, '_', 3)::bigint < {cutoff} \
                     ELSE true END) \
         ORDER BY random()"
    );

    let started = Instant::now();
    let Ok(rows) = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
        .fetch_all(&mut *admin)
        .await
    else {
        return;
    };

    // Bound each drop on the server too — the budget below is checked
    // between drops and cannot interrupt one in flight.
    let _ = admin
        .execute(sqlx::AssertSqlSafe(format!(
            "SET lock_timeout = {DROP_LOCK_TIMEOUT_MS}; \
             SET statement_timeout = {DROP_STATEMENT_TIMEOUT_MS}"
        )))
        .await;

    let outcome = drop_within_budget(rows, SWEEP_BUDGET, &mut SqlDrop(&mut *admin)).await;

    // Hand the connection back as it was: `isolated_db_from` runs
    // `CREATE DATABASE` and the migration set on it next, and cancelling
    // either one fails the test that asked for the database. `RESET`
    // restores the server/role default rather than pinning the session
    // to unbounded, which would silently widen a deployment that sets
    // one.
    let _ = admin
        .execute(sqlx::AssertSqlSafe(
            "RESET lock_timeout; RESET statement_timeout",
        ))
        .await;

    report_sweep(&outcome, started.elapsed());
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Create a uniquely-named database (derived from `base_url`: same
/// host/user/password, fresh dbname) and return a pool connected to it.
/// The DB is **empty** — the caller runs its own
/// `sqlx::migrate!().run()` on the returned pool.
///
/// Returns `None` on any failure (mirrors the prior
/// `PgPool::connect(&url).await.ok()?` semantics so the suite stays
/// green when `DATABASE_URL` is unset / the DB is unreachable).
pub async fn isolated_db_from(base_url: &str) -> Option<PgPool> {
    let opts: PgConnectOptions = base_url.parse().ok()?;
    // The epoch segment is load-bearing: `sweep_stale_databases` reads
    // it to age-gate candidates. Keep the `hort_test_<epoch>_<uuid>`
    // shape if you rename this.
    let db = format!(
        "hort_test_{}_{}",
        now_unix_secs(),
        uuid::Uuid::new_v4().simple()
    );

    // CREATE DATABASE cannot run in a transaction or target the
    // connected DB — use a maintenance connection to `postgres`.
    let mut admin = PgConnection::connect_with(&opts.clone().database("postgres"))
        .await
        .ok()?;

    // Once per process, on the connection we already hold.
    sweep_stale_databases(&mut admin).await;

    admin
        .execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{db}\"")))
        .await
        .ok()?;
    let _ = admin.close().await;

    let pool = PgPool::connect_with(opts.database(&db)).await.ok()?;

    // Migrate here, with a bounded retry. Per-test DB isolation means
    // ~80+ test binaries each `CREATE DATABASE` + run the full
    // (DDL-heavy, cluster-global `CREATE ROLE`) migration set
    // concurrently against one Postgres; that thundering herd
    // intermittently makes a single migration run fail on shared-catalog
    // lock contention. A few spaced retries absorb the transient
    // contention. On persistent failure the pool is still returned: the
    // call site's own `sqlx::migrate!().run()` then runs (a no-op once
    // migrated; otherwise it surfaces the real error via its `.expect`,
    // so a genuine migration bug is never masked into a silent skip).
    for attempt in 0..4u32 {
        match sqlx::migrate!("../../migrations").run(&pool).await {
            Ok(()) => break,
            Err(_) if attempt < 3 => {
                tokio::time::sleep(Duration::from_millis(150 * u64::from(attempt + 1))).await;
            }
            Err(_) => break,
        }
    }
    Some(pool)
}

/// Connect to the shared `DATABASE_URL` target — not a per-test isolated
/// database — and ensure it is migrated before handing back the pool.
///
/// For tests that deliberately exercise shared-DB behavior under the
/// `#[serial(hort_pg_db)]` contract (isolation would defeat the point of
/// the test). Every caller against the shared target must migrate through
/// here: `#[serial(hort_pg_db)]` name-orders tests within a binary, but
/// gives no ordering guarantee *across* the several modules that share
/// this database, so no test may assume an earlier-sorting module already
/// migrated it.
///
/// Returns `None` when `DATABASE_URL` is unset or the target is
/// unreachable (mirrors [`isolated_db_from`]'s self-skip semantics). A
/// migration that fails after retries is a real bug, not a skip
/// condition, and panics rather than handing back an unmigrated pool.
pub async fn shared_migrated_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPool::connect(&url).await.ok()?;

    // Bounded retry: the shared target is a migration race between every
    // test binary that reaches this helper concurrently, the same
    // thundering-herd contention `isolated_db_from` absorbs above.
    let mut last_err = None;
    for attempt in 0..4u32 {
        match sqlx::migrate!("../../migrations").run(&pool).await {
            Ok(()) => return Some(pool),
            Err(err) => {
                last_err = Some(err);
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_millis(150 * u64::from(attempt + 1))).await;
                }
            }
        }
    }
    panic!("migrations failed against the shared DATABASE_URL target after retries: {last_err:?}");
}

/// Run the embedded migration set against `pool`, panicking with a message
/// that names the actual failure instead of asserting the migrations ran.
///
/// `sqlx::migrate!().run()` can fail before a single migration statement
/// executes: a pool that cannot hand out a connection within its timeout
/// surfaces as `MigrateError::Execute(sqlx::Error::PoolTimedOut)`, which
/// looks — to a message that just says "migrations failed" — identical to a
/// broken migration. It is not: the migration set was never reached. This
/// classifies that case at the point it happens so the panic names
/// connection acquisition, not migrations, while a genuine migration
/// failure still gets the accurate migration message. Either way the
/// underlying error rides along in the panic payload.
///
/// `sqlx::migrate!` embeds relative to the crate that expands it, so calling
/// this from any crate embeds *this* crate's `../../migrations` — the one
/// workspace-root migration set every caller already runs today.
pub async fn migrate_or_panic(pool: &PgPool) {
    if let Err(err) = sqlx::migrate!("../../migrations").run(pool).await {
        panic!("{}", classify_migrate_failure(&err));
    }
}

/// True when `err` reflects a connection that was never acquired — the pool
/// timed out waiting for one, or was closed out from under the wait — rather
/// than a failure encountered while actually executing a migration.
fn is_acquisition_failure(err: &sqlx::migrate::MigrateError) -> bool {
    matches!(
        err,
        sqlx::migrate::MigrateError::Execute(sqlx::Error::PoolTimedOut)
            | sqlx::migrate::MigrateError::Execute(sqlx::Error::PoolClosed)
    )
}

/// Build the panic message for a failed migration run. Split out from
/// [`migrate_or_panic`] so it can be exercised without a database: construct
/// a `MigrateError` directly and check which message shape comes back.
fn classify_migrate_failure(err: &sqlx::migrate::MigrateError) -> String {
    if is_acquisition_failure(err) {
        format!(
            "connection acquisition timed out before migrations ran — this is \
             contention for a connection, not a broken migration. Check for another \
             `cargo test` run or a sibling DB-backed test target hitting the same \
             Postgres server concurrently. Pool sizing is not the thing to change: \
             measured peak usage is ~10 concurrent backends against ~97 usable. \
             Underlying error: {err}"
        )
    } else {
        format!("migrations failed to run cleanly against the test DB: {err}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`DropCandidate`] whose every drop costs a fixed amount of time.
    /// Under `tokio::test(start_paused = true)` that time is virtual, so
    /// the budget loop is exercised against a drop far slower than any real
    /// one without the test taking any wall clock at all.
    struct SlowDrop {
        per_drop: Duration,
        succeeds: bool,
        seen: Vec<String>,
    }

    impl SlowDrop {
        fn taking(per_drop: Duration) -> Self {
            Self {
                per_drop,
                succeeds: true,
                seen: Vec::new(),
            }
        }
    }

    impl DropCandidate for SlowDrop {
        async fn drop_candidate(&mut self, name: &str) -> bool {
            self.seen.push(name.to_string());
            tokio::time::sleep(self.per_drop).await;
            self.succeeds
        }
    }

    fn candidates(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| format!("hort_test_1700000000_{i}"))
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn the_loop_stops_on_the_budget_against_a_slow_drop() {
        let mut dropper = SlowDrop::taking(Duration::from_millis(400));
        let started = Instant::now();

        let outcome =
            drop_within_budget(candidates(100), Duration::from_secs(1), &mut dropper).await;

        // The clock is checked before each drop: 0 ms, 400 ms and 800 ms are
        // inside the budget, the check at 1200 ms is not.
        assert_eq!(outcome.attempted, 3, "{outcome:?}");
        assert_eq!(outcome.dropped, 3, "{outcome:?}");
        assert_eq!(outcome.candidates, 100, "{outcome:?}");
        assert!(outcome.exhausted_budget, "{outcome:?}");
        assert_eq!(
            dropper.seen.len(),
            3,
            "only the attempted candidates are touched"
        );
        let elapsed = started.elapsed();
        assert!(
            (Duration::from_millis(1200)..=Duration::from_millis(1400)).contains(&elapsed),
            "loop must return at the budget plus at most one drop, took {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn one_pathological_drop_overruns_the_budget_and_nothing_follows_it() {
        // The honest limit of a budget checked between drops: it cannot
        // interrupt one in flight. `DROP_STATEMENT_TIMEOUT_MS` is what bounds
        // this tail on the server; the loop's own guarantee stops here, and
        // this test pins that rather than implying otherwise.
        let mut dropper = SlowDrop::taking(Duration::from_secs(120));
        let started = Instant::now();

        let outcome = drop_within_budget(candidates(5), Duration::from_secs(1), &mut dropper).await;

        assert_eq!(outcome.attempted, 1, "{outcome:?}");
        assert!(outcome.exhausted_budget, "{outcome:?}");
        assert!(started.elapsed() >= Duration::from_secs(120));
    }

    #[tokio::test(start_paused = true)]
    async fn a_steady_state_list_is_drained_in_full_inside_the_budget() {
        // ~437 databases per workspace run over the 36 processes that sweep is
        // ~12 candidates each, at the 200 ms per drop measured while a run is
        // in progress (not the 60–80 ms an idle server gives).
        let mut dropper = SlowDrop::taking(Duration::from_millis(200));

        let outcome = drop_within_budget(candidates(12), SWEEP_BUDGET, &mut dropper).await;

        assert_eq!(outcome.attempted, 12, "{outcome:?}");
        assert_eq!(outcome.dropped, 12, "{outcome:?}");
        assert!(!outcome.exhausted_budget, "{outcome:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_drop_is_attempted_but_not_counted_as_dropped() {
        let mut dropper = SlowDrop::taking(Duration::from_millis(10));
        dropper.succeeds = false;

        let outcome = drop_within_budget(candidates(3), SWEEP_BUDGET, &mut dropper).await;

        assert_eq!(outcome.attempted, 3, "{outcome:?}");
        assert_eq!(outcome.dropped, 0, "{outcome:?}");
        assert!(
            !outcome.exhausted_budget,
            "a skipped candidate is not a spent budget"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_candidate_list_is_not_a_budget_exhaustion() {
        let mut dropper = SlowDrop::taking(Duration::from_secs(600));

        let outcome = drop_within_budget(Vec::new(), SWEEP_BUDGET, &mut dropper).await;

        assert_eq!(outcome, SweepOutcome::default());
    }

    #[test]
    fn a_sweep_that_finished_its_list_says_nothing() {
        let outcome = SweepOutcome {
            candidates: 12,
            attempted: 12,
            dropped: 12,
            exhausted_budget: false,
        };
        assert_eq!(budget_warning(&outcome, Duration::from_millis(900)), None);
    }

    #[test]
    fn a_sweep_that_ran_out_of_budget_carries_the_numbers_that_explain_it() {
        let outcome = SweepOutcome {
            candidates: 1251,
            attempted: 37,
            dropped: 36,
            exhausted_budget: true,
        };
        let warning = budget_warning(&outcome, Duration::from_millis(3040))
            .expect("an exhausted budget must be reported");
        for fragment in ["1251", "37", "36", "3040"] {
            assert!(
                warning.contains(fragment),
                "warning must carry {fragment}: {warning}"
            );
        }
    }

    #[test]
    fn pool_timed_out_is_classified_as_acquisition_not_migrations() {
        let err = sqlx::migrate::MigrateError::Execute(sqlx::Error::PoolTimedOut);
        let message = classify_migrate_failure(&err);
        assert!(
            message.contains("connection acquisition"),
            "expected an acquisition-shaped message, got: {message}"
        );
        assert!(
            !message.contains("migrations failed"),
            "must not blame migrations for a connection that was never acquired: {message}"
        );
        assert!(
            message.contains("pool timed out"),
            "must retain the underlying error: {message}"
        );
    }

    #[test]
    fn pool_closed_is_also_classified_as_acquisition() {
        let err = sqlx::migrate::MigrateError::Execute(sqlx::Error::PoolClosed);
        let message = classify_migrate_failure(&err);
        assert!(
            message.contains("connection acquisition"),
            "expected an acquisition-shaped message, got: {message}"
        );
        assert!(
            message.contains("closed"),
            "must retain the underlying error: {message}"
        );
    }

    #[test]
    fn a_genuine_migration_failure_keeps_the_migration_meaning() {
        let err = sqlx::migrate::MigrateError::VersionMissing(7);
        let message = classify_migrate_failure(&err);
        assert!(
            message.contains("migrations failed"),
            "expected the migration-failure message, got: {message}"
        );
        assert!(
            message.contains('7'),
            "must retain the underlying error: {message}"
        );
    }
}
