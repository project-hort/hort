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
//! ## The skip contract: one condition, and it is not "the DB is down"
//!
//! A DB-gated test skips on exactly one condition — `DATABASE_URL`
//! unset — and that decision is taken by the caller, not here. Every
//! call site is `let url = env::var("DATABASE_URL").ok()?;` immediately
//! followed by [`isolated_db_from`], so this module is only ever asked
//! for a database the operator has declared. From that point a failure
//! is a hard failure: [`isolated_db_from`], [`connect_or_panic`] and
//! [`shared_migrated_pool`] panic rather than hand back a `None` the
//! caller cannot tell apart from "no database configured".
//!
//! They did hand back that `None`, and the cost of it was not an
//! uncertain result but a false one. Measured against a closed port,
//! `cargo test --workspace --tests --no-fail-fast` reported **12,350
//! passed, 1 failed, 7 ignored** — 488 of the 489 tests that touch the
//! database claiming `ok` without having opened a connection, and none
//! of them counted in the `ignored` column. The one failure was the single test in the
//! workspace that hand-rolled `.expect()` on its own maintenance
//! connection. The state in which a green gate is most valuable — the
//! server has a problem — was the state in which the gate inverted.
//!
//! ## Cleanup — a once-per-process sweep
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
//! That was the whole of the "flakiness" the sweep was written for, and
//! it is not historical: measured again at **1,109 databases**, an
//! unclean stop cost **339 seconds** of recovery, every connection in
//! that window answering `57P03 the database system is in recovery
//! mode`.
//!
//! The sweep is safe by construction, not by luck. Two things have to
//! hold before a candidate is dropped, and between them they say
//! "nobody owns this any more":
//!
//! - **No live connection.** A candidate with any backend against it in
//!   `pg_stat_activity` is skipped — and [`isolated_db_from`] builds its
//!   pool through [`per_test_pool_options`], which sets
//!   `min_connections = 1`, so that backend exists from before
//!   [`isolated_db_from`] returns until the owning test drops the pool.
//!   Ownership is *published continuously* rather than inferred from a
//!   query that happened to be in flight: no backend means the owning
//!   pool is gone. Postgres backs the check up at the last moment too —
//!   a `DROP DATABASE` against a database somebody connected to since
//!   the candidate query simply fails, which is the skip path every
//!   other failure here already takes.
//! - **Age.** The one moment the connection signal cannot cover is the
//!   window between `CREATE DATABASE` and the pool's first connection.
//!   The database name carries its creation time
//!   (`hort_test_<unix_secs>_<uuid>`) and [`STALE_AFTER_SECS`] covers
//!   that window — only that window, which is what lets it be short.
//!
//! And every step is best-effort: any error is ignored and the caller
//! proceeds to create its own database. Cleanup must never be the
//! reason a test fails.
//!
//! It does not *prevent* a leak — a drop-on-teardown guard would, at the
//! cost of a guard type threaded through the 60 files that call
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
//! nothing the harness controls: single `DROP DATABASE`s have been
//! observed waiting 136 and 186 seconds for their checkpoints while
//! other processes ran migration sets, and 73 seconds on `Lock/object`
//! when two test
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
//! Candidates are taken in random order (within each class of the
//! two-key order below) for the same reason: sweeps that walk one stable
//! order meet on the same first candidates, which is the
//! `Lock/object` measurement above. Re-dropping a candidate a peer
//! already removed is free (`DROP DATABASE IF EXISTS` on an absent name
//! returns in under a millisecond — no checkpoint), so overlap costs
//! nothing beyond the lock wait that [`DROP_LOCK_TIMEOUT_MS`] bounds.
//!
//! ### A fourth bound, because holding the cost is not the same as coming out ahead
//!
//! The three above bound what a sweep costs. For a long time nothing
//! bounded what it *wasted*, and it wasted all of it. The failure is specific: every
//! `DROP DATABASE` ends in `RequestCheckpoint(CHECKPOINT_IMMEDIATE |
//! CHECKPOINT_FORCE | CHECKPOINT_WAIT)`, and `CHECKPOINT_WAIT` waits for
//! a checkpoint cycle that *begins after* the request. While the
//! checkpointer is already busy — which, under the WAL of ~400
//! `CREATE DATABASE`s and their migration sets, is most of a workspace
//! run — a drop waits out the running cycle and then its own. Past
//! [`DROP_STATEMENT_TIMEOUT_MS`] that wait is cancelled; the next
//! candidate queues *another* forced checkpoint behind the same backlog
//! and is cancelled the same way. Such a sweep spends its whole budget,
//! drops nothing, and has added one forced checkpoint per attempt to the
//! queue it was stuck behind — it degrades the server it is waiting on.
//! Observed in the field as `4 attempted, 0 dropped` twice running at an
//! unchanged candidate count, and once at `880 candidates, 4 attempted,
//! 0 dropped`.
//!
//! **Finishing a cancelled drop later is not cheaper**, so the wasted
//! attempt buys nothing to collect afterwards. PostgreSQL 16 does commit
//! the "invalid database" marker before the destructive phase (see
//! below), so a cancelled drop leaves real work behind — but the cost is
//! the checkpoint, and the second attempt pays it again in full.
//! Measured against an idle PostgreSQL 16.14: eight candidates cancelled
//! at a 20 ms `statement_timeout`, all eight left at
//! `pg_database.datconnlimit = -2`, then dropped untimed, cost 69, 73,
//! 74, 75, 76, 95, 108 and 111 ms — against 59–82 ms for thirteen
//! never-cancelled drops in the same session. Re-dropping is an ordinary
//! drop, not a cheap finish.
//!
//! Hence the fourth bound, [`TIMEOUTS_BEFORE_GIVING_UP`]: two drops
//! cancelled on the server's clock with none completing in between means
//! the server cannot finish one right now, and the useful thing to do
//! with the rest of the budget is hand it back. It is not a bound on
//! cost — [`SWEEP_BUDGET`] already holds that — it is the bound that
//! stops the sweep making the thing it is waiting for worse. The sweep
//! is best-effort: a run that cannot clean up this time cleans up next
//! time.
//!
//! The candidate *order* carries the other half. A cancelled drop leaves
//! an invalid database behind, and under `ORDER BY random()` over
//! hundreds of candidates it is essentially never revisited, so those
//! half-destroyed databases accumulate as their own population. Invalid
//! candidates are therefore taken first, which turns them into a short
//! queue the next sweep finishes instead. They are also the safest
//! candidates there are: `datconnlimit = -2` is set only by an
//! interrupted `DROP DATABASE` (`ALTER DATABASE … CONNECTION LIMIT`
//! rejects anything below `-1`), and a database nobody can connect to is
//! a database nobody is about to use.
//!
//! ### What the bound guarantees
//!
//! One sweep holds `#[serial(hort_pg_db)]` for at most [`SWEEP_BUDGET`]
//! plus [`DROP_STATEMENT_TIMEOUT_MS`], and when the server is in the
//! state above for much less than that —
//! [`TIMEOUTS_BEFORE_GIVING_UP`] drops, so at most
//! `TIMEOUTS_BEFORE_GIVING_UP × DROP_STATEMENT_TIMEOUT_MS`. All of it is
//! verified rather than assumed: the loop's budget and its give-up rule
//! by this module's DB-free tests against an artificially slowed drop,
//! and the statement timeout against a real server — a `DROP DATABASE`
//! parked on `IPC/CheckpointStart`/`IPC/CheckpointDone` is cancelled at
//! exactly the configured deadline with SQLSTATE 57014. A checkpoint
//! wait is not a lock wait, so that one had to be measured.
//!
//! Interrupting a `DROP DATABASE` is *safe*, not merely tolerated, and
//! that is a property of the server version: PostgreSQL 16 commits an
//! "invalid database" marker (`pg_database.datconnlimit = -2`) before
//! the destructive phase, so a cancelled drop leaves a database that
//! cannot be connected to, is still matched by the candidate query, and
//! is finished by the next sweep — at the price of an ordinary drop,
//! not of a cheap finish, which is why the candidate order puts it
//! first rather than leaving it to chance. Both CI pipelines and the
//! sandbox run PostgreSQL 16; on an older server an interrupted drop
//! carries no such guarantee, and [`DROP_STATEMENT_TIMEOUT_MS`] would
//! have to be re-justified there.
//!
//! ### What the bound does not guarantee
//!
//! It does not bound the *population*. A budget bounds what one sweep
//! costs, not how many databases exist: if `CREATE DATABASE` outruns the
//! aggregate drain rate across a run's sweeping processes, the
//! population still climbs. The only thing that says so is the line
//! [`report_sweep`] writes to stderr when a sweep stops early — on its
//! budget, or on [`TIMEOUTS_BEFORE_GIVING_UP`].
//!
//! It is not what keeps `/dev/shm` from filling, and the sweep should
//! not be read as existing for that. `/dev/shm` fills with orphaned
//! dynamic-shared-memory segments, one batch per run; dropping every
//! test database back to zero frees about 2 MB of a 63 MB container
//! `--shm-size` that is set outside this repository. The population is
//! at most a multiplier there, and shrinking it is no substitute for
//! raising the ceiling.
//!
//! What stale databases actually cost is enough on its own: ~10 MB of
//! files each, a `pg_database` that every sweep's own candidate query
//! and every connection's catalogue lookup walk, and a startup that
//! replays all of it after an unclean stop — the 339-second recovery
//! above, with every connection in that window answering `57P03`.
//! Catalogue ballast and a slow harness is the whole of the claim, and
//! it is reason enough.
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
//! test databases connected at once: cargo runs test binaries one at a
//! time and a per-test pool lives only as long as its test, so they
//! never approach the server's limit. ([`per_test_pool_options`] holds
//! one connection per live pool rather than letting a pool fall to
//! zero, which is a change of one or two backends against that
//! headroom, and it is load-bearing for the sweep's safety argument.)
//! And a second
//! process's full acquisition path — connect, `CREATE DATABASE`, build
//! the pool, `acquire`, run the whole migration set — showed no
//! degradation at all across a 242-second sweep of 600 databases: every
//! one of its 90 `acquire` calls returned in under a millisecond. A
//! timeout here is not a connection budget that is full, so a smaller
//! pool would change nothing.

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::time::Duration;
// `tokio::time::Instant` rather than `std::time::Instant` so
// `tokio::test(start_paused = true)` can drive the budget loop through
// virtual time; outside a paused runtime the two behave identically.
use tokio::time::Instant;

/// Age below which a stray `hort_test_*` database is left alone.
///
/// This covers one window and nothing else: between `CREATE DATABASE` in
/// [`isolated_db_from`] and the first connection of the pool it builds
/// immediately afterwards. Before that window the database does not
/// exist; after it, ownership is published continuously, because
/// [`per_test_pool_options`] keeps `min_connections = 1` and sqlx
/// re-opens a reaped connection in the same maintenance pass that closed
/// it. "No backend in `pg_stat_activity`" therefore means "the owning
/// pool is gone", for the whole of a test's life rather than only while
/// it happens to be querying.
///
/// Measured, the window is **31–49 ms**: ten `CREATE DATABASE` calls
/// followed by [`per_test_pool_options`]`.connect_with`, timed from the
/// create returning to the pool being ready (32.7, 31.1, 33.9, 32.8,
/// 35.7, 48.3, 32.5, 43.8, 43.1, 46.5 ms) and polled on to the backend
/// becoming visible in `pg_stat_activity`, which trailed by another
/// 0.6–1.2 ms.
///
/// The window has its own ceiling, and this constant is derived from
/// that rather than from the measurement: the pool's first connect
/// retries `ConnectionRefused` / `57P03` / `53300` with backoff until
/// sqlx's `acquire_timeout` and [`isolated_db_from`] panics after that,
/// so a database cannot sit unconnected for longer than
/// `acquire_timeout` and still be wanted by anybody. Two minutes is four
/// times sqlx's 30-second default — and some 2,400 times the window
/// actually measured. `the_age_gate_outlasts_the_create_to_first_connect_window`
/// pins the ratio to the ceiling, so lowering this without lowering the
/// other fails the suite.
///
/// **This is a safety property, not a tuning knob**, and the two halves
/// move together: shortening it is only legitimate while something else
/// covers the window it stops covering. Ten minutes was derived from
/// sqlx's ten-minute `idle_timeout`, back when an idle pool stopped
/// publishing ownership and the gate had to outlast that silence.
/// `min_connections = 1` removes the premise. One hour, before that,
/// exceeded the interval between runs during active development, so a
/// run reclaimed neither its own databases nor usually its predecessor's
/// and the population climbed monotonically — four `cargo test
/// --workspace` runs against a cluster reset to zero left **1,251
/// databases / 11 GB** standing, where one run creates **~430**.
///
/// Ten minutes did not fix that so much as halve it. A workspace run
/// takes about ten minutes, so a run's own databases aged past the gate
/// only as the run ended and were reclaimed by the *next* run, never by
/// this one: 270 standing against 13 candidates, measured mid-run. The
/// drain was entirely cross-run and the steady state was a whole run's
/// worth of databases. At two minutes a database created in the first
/// four fifths of a ten-minute run is reclaimable by that run's own
/// later processes, which is what the module doc's self-healing claim
/// needs in order to be true of the run making it.
const STALE_AFTER_SECS: u64 = 120;

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

/// How many drops the server may cancel on its own clock, with none
/// completing in between, before the sweep stops.
///
/// A cancelled drop is a checkpoint the sweep asked for and did not get,
/// and the next candidate asks for another one behind the same backlog —
/// so past the first cancellation the sweep is spending its budget to
/// make the queue it is waiting on longer. Two rather than one because a
/// single cancellation can be a candidate that merely arrived while a
/// checkpoint was already running; two in a row, with no drop completing
/// between them, is the server. Two also keeps the whole give-up path
/// inside [`SWEEP_BUDGET`] (2 × 1.5 s against 5 s), so it is the budget
/// that is handed back rather than overrun.
const TIMEOUTS_BEFORE_GIVING_UP: usize = 2;

/// The marker PostgreSQL 16 writes to `pg_database.datconnlimit` before
/// the destructive phase of `DROP DATABASE`, so that an interrupted drop
/// leaves a database nothing can connect to rather than a half-deleted
/// one that looks usable.
///
/// Only `dropdb()` ever writes it: `ALTER DATABASE … CONNECTION LIMIT`
/// rejects anything below `-1`. So a `hort_test_*` database carrying it
/// is one a sweep already condemned — the safest candidate in the list,
/// and the one to finish before condemning another. On a server older
/// than 16 the column never holds this value and the clause that reads
/// it is simply never true.
const DATCONNLIMIT_INVALID_DB: i32 = -2;

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
/// Giving up must be something the sweep does *with* budget left, not an
/// alternative spelling of spending it: if the cancellations it tolerates
/// could themselves fill [`SWEEP_BUDGET`], the loop would stop on the
/// clock and the give-up rule would never be reached.
const _: () = assert!(
    TIMEOUTS_BEFORE_GIVING_UP as u64 * DROP_STATEMENT_TIMEOUT_MS < SWEEP_BUDGET.as_millis() as u64,
    "the tolerated cancellations must fit inside the budget, or giving up never happens"
);

/// How the per-test pool is built, and the half of the sweep's safety
/// argument that does not live in the sweep.
///
/// `min_connections = 1` is not a performance setting. It is what makes
/// "no backend against this database in `pg_stat_activity`" mean "the
/// owning pool is gone": sqlx establishes the minimum before
/// `connect_with` returns, will not reap below it, and re-opens a
/// connection in the same maintenance pass that closes one past
/// `idle_timeout` or `max_lifetime`. Without it a pool that has not been
/// queried for ten minutes stops publishing its ownership while the test
/// holding it is still running, and the only thing left between that
/// database and the sweep is [`STALE_AFTER_SECS`] — which is why that
/// constant used to have to be as long as a whole workspace run.
///
/// Everything else stays at sqlx's defaults, for the reason the module
/// doc gives at length: measured peak usage across a whole workspace run
/// is ~11 concurrent backends against 97 usable, so the pool is nowhere
/// near a limit worth tuning.
fn per_test_pool_options() -> PgPoolOptions {
    PgPoolOptions::new().min_connections(1)
}

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
    async fn drop_candidate(&mut self, name: &str) -> DropVerdict;
}

/// What one drop attempt did — and, when it did not succeed, whose
/// problem that was.
///
/// The distinction is the whole point: a failure that belongs to the
/// *candidate* says nothing about the next one, while a failure that
/// belongs to the *server's clock* says the next one will fail the same
/// way. Collapsing both into `false` is what let a sweep spend its whole
/// budget learning the same thing four times.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropVerdict {
    /// The candidate is gone.
    Dropped,
    /// The drop failed for a reason that belongs to this candidate: a
    /// connection arrived since the candidate query, a peer sweeper held
    /// the object lock past [`DROP_LOCK_TIMEOUT_MS`], the role lost the
    /// privilege. Cheap, local, and no evidence about the next
    /// candidate.
    Skipped,
    /// The server cancelled the drop on [`DROP_STATEMENT_TIMEOUT_MS`]
    /// (SQLSTATE 57014). The drop was waiting for a checkpoint cycle it
    /// did not get, and the next candidate would queue another forced
    /// checkpoint behind the same backlog.
    OutOfTime,
}

/// Read a failed `DROP DATABASE` as a [`DropVerdict`].
///
/// Only `statement_timeout` is read as the server's clock. A
/// `lock_timeout` (SQLSTATE 55P03) is deliberately [`DropVerdict::Skipped`]
/// even though it is also a clock: a held object lock means a concurrent
/// sweeper is already dropping *that* candidate, which is both local to
/// the candidate and work that is getting done anyway.
fn verdict_for(err: &sqlx::Error) -> DropVerdict {
    const QUERY_CANCELED: &str = "57014";
    match err {
        sqlx::Error::Database(db) if db.code().as_deref() == Some(QUERY_CANCELED) => {
            DropVerdict::OutOfTime
        }
        _ => DropVerdict::Skipped,
    }
}

/// [`DropCandidate`] backed by the real maintenance connection.
struct SqlDrop<'a>(&'a mut PgConnection);

impl DropCandidate for SqlDrop<'_> {
    async fn drop_candidate(&mut self, name: &str) -> DropVerdict {
        // DROP DATABASE cannot run in a transaction; a concurrent
        // connection arriving between the query and here makes this
        // fail, which is exactly the outcome we want — skip it.
        match self
            .0
            .execute(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS \"{name}\""
            )))
            .await
        {
            Ok(_) => DropVerdict::Dropped,
            Err(err) => verdict_for(&err),
        }
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
    /// Candidates the server cancelled on [`DROP_STATEMENT_TIMEOUT_MS`].
    timed_out: usize,
    /// True when the loop stopped on the clock rather than on the end of
    /// the candidate list — i.e. the population is outrunning the sweep.
    exhausted_budget: bool,
    /// True when the loop stopped because the server cancelled
    /// [`TIMEOUTS_BEFORE_GIVING_UP`] drops in a row without completing
    /// one — i.e. the server cannot finish a `DROP DATABASE` right now
    /// and the rest of the budget would go on making that worse.
    gave_up_on_timeouts: bool,
}

/// Drop `names` one at a time until the list is done, `budget` is spent,
/// or the server has shown it cannot finish a drop.
///
/// The clock is checked *between* drops, so the loop returns at `budget`
/// plus at most one drop — it cannot interrupt a drop already in flight.
/// That tail is bounded server-side instead, by
/// [`DROP_STATEMENT_TIMEOUT_MS`]; without it the tail is whatever one
/// `DROP DATABASE` costs, which is unbounded.
///
/// The third exit is [`TIMEOUTS_BEFORE_GIVING_UP`]. The counter resets on
/// a completed drop and on nothing else, so the rule reads exactly as
/// "that many cancellations with no drop between them" — a sweep that has
/// been working and then meets one slow candidate keeps its budget, and a
/// sweep that has achieved nothing hands it back.
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
    let mut timeouts_since_last_drop = 0usize;
    for name in names {
        if started.elapsed() >= budget {
            outcome.exhausted_budget = true;
            break;
        }
        outcome.attempted += 1;
        match dropper.drop_candidate(&name).await {
            DropVerdict::Dropped => {
                outcome.dropped += 1;
                timeouts_since_last_drop = 0;
            }
            DropVerdict::Skipped => {}
            DropVerdict::OutOfTime => {
                outcome.timed_out += 1;
                timeouts_since_last_drop += 1;
                if timeouts_since_last_drop >= TIMEOUTS_BEFORE_GIVING_UP {
                    outcome.gave_up_on_timeouts = true;
                    break;
                }
            }
        }
    }
    outcome
}

/// The one line a sweep owes a human, or `None` when it owes none.
///
/// A sweep that finished its candidate list is not news, and 36 test
/// processes per workspace run each announcing themselves would train the
/// reader to skip the line. Two states need somebody, and they want
/// different things done about them, so they say different things.
fn sweep_warning(outcome: &SweepOutcome, elapsed: Duration) -> Option<String> {
    let numbers = format!(
        "{} candidates, {} attempted, {} dropped, {} cancelled on the {} ms per-drop timeout",
        outcome.candidates,
        outcome.attempted,
        outcome.dropped,
        outcome.timed_out,
        DROP_STATEMENT_TIMEOUT_MS,
    );
    // Checked first: a sweep that gave up has, by construction, budget
    // left, so the two states cannot both be true — but saying "ran out
    // of budget" about a sweep that stopped early would send the reader
    // after the wrong thing.
    if outcome.gave_up_on_timeouts {
        return Some(format!(
            "hort test-database sweep gave up after {} ms: {numbers}. The server cancelled \
             {TIMEOUTS_BEFORE_GIVING_UP} drops in a row without finishing one, so the sweep \
             stopped rather than queue more forced checkpoints behind the one it was waiting \
             on. Every `DROP DATABASE` waits for an immediate checkpoint; when the \
             checkpointer is this far behind, no sweep drains anything and stale \
             `hort_test_*` databases accumulate. Look at what else is writing to this server.",
            elapsed.as_millis(),
        ));
    }
    if outcome.exhausted_budget {
        return Some(format!(
            "hort test-database sweep stopped on its {}s budget after {} ms: {numbers}. Stale \
             `hort_test_*` databases are accumulating faster than the per-process sweep drains \
             them — check the server for slow or contended DROP DATABASE.",
            SWEEP_BUDGET.as_secs(),
            elapsed.as_millis(),
        ));
    }
    None
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
        timed_out = outcome.timed_out,
        exhausted_budget = outcome.exhausted_budget,
        gave_up_on_timeouts = outcome.gave_up_on_timeouts,
        elapsed_ms = elapsed.as_millis(),
        "swept stale test databases"
    );
    if let Some(warning) = sweep_warning(outcome, elapsed) {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "{warning}");
    }
}

/// The sweep's candidate list: `hort_test_*` databases nobody is
/// connected to whose epoch segment is before `cutoff`, worst first.
///
/// `split_part(datname, '_', 3)` is the epoch segment of
/// `hort_test_<epoch>_<uuid>`. Databases predating the timestamped
/// naming have a non-numeric segment there; `~ '^[0-9]+$'` excludes them
/// from the age test, and the second arm sweeps them on the connection
/// check alone (they are, by definition, older).
///
/// The order is two keys. Already-invalid databases first, because a
/// sweep that was cancelled mid-drop leaves them behind and under
/// `random()` alone they are never revisited — a population of
/// half-destroyed databases growing beside the one being drained.
/// `random()` within each class for the original reason: `DROP DATABASE`
/// takes an exclusive lock on the database object, so two sweeps walking
/// one stable order serialise against each other on their first
/// candidates. The whole list is still fetched — its length is the
/// diagnostic the warning carries.
///
/// Split out from [`sweep_stale_databases`] so the predicates can be run
/// against a real server from a test that owns the database it is asking
/// about.
fn candidate_query(cutoff: u64) -> String {
    format!(
        "SELECT d.datname FROM pg_database d \
         LEFT JOIN (SELECT datname, count(*) AS cnt FROM pg_stat_activity GROUP BY datname) a \
           ON a.datname = d.datname \
         WHERE d.datname LIKE 'hort\\_test\\_%' \
           AND COALESCE(a.cnt, 0) = 0 \
           AND (CASE WHEN split_part(d.datname, '_', 3) ~ '^[0-9]+$' \
                     THEN split_part(d.datname, '_', 3)::bigint < {cutoff} \
                     ELSE true END) \
         ORDER BY (d.datconnlimit = {DATCONNLIMIT_INVALID_DB}) DESC, random()"
    )
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

    let started = Instant::now();
    let sql = candidate_query(cutoff);
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

/// Credential-free description of what a set of connection options
/// points at, for a panic message that will land in a CI log.
///
/// Host and port only. The project redacts `database_url` wholesale in
/// every `Debug` impl that touches it (`hort-server` / `hort-worker`
/// `config.rs`); a panic message is no different, and the password is
/// never diagnostic.
fn connection_target(opts: &PgConnectOptions) -> String {
    format!("{}:{}", opts.get_host(), opts.get_port())
}

/// The panic message a configured-but-unusable `DATABASE_URL` earns,
/// with `stage` naming the step that failed.
///
/// Split out from its call sites so the wording — and, more to the
/// point, the guarantee that it carries no credential — is exercised
/// without a database, exactly as [`classify_migrate_failure`] is.
///
/// `err` is a sqlx error from a connect, a `CREATE DATABASE`, or a URL
/// parse. None of those echo the connection string: sqlx's
/// configuration error wraps a `url`/`ParseInt`/`AddrParse` error whose
/// `Display` names the defect, not the input, and a connect error names
/// a host, an OS errno or a SQLSTATE.
fn unusable_database_message(stage: &str, target: &str, err: &dyn std::fmt::Display) -> String {
    format!(
        "DATABASE_URL is set (target {target}) but {stage} failed: {err}\n\
         This is a hard failure, not a skip. Reaching this point means the \
         caller read DATABASE_URL and got a value — the operator declaring \
         that a database exists — so there is no database only in the sense \
         that the declared one could not be used. Returning a skip here would \
         report a test that never ran as `ok`, which inverts the gate exactly \
         when the server is unwell. To run the workspace suite DB-free, unset \
         DATABASE_URL."
    )
}

/// Connect a pool to an explicitly-configured `DATABASE_URL`, panicking
/// rather than skipping when the connection cannot be made.
///
/// The shared entry point for the DB-gated fixtures that need a pool on
/// the `DATABASE_URL` target itself rather than a per-test database from
/// [`isolated_db_from`] — the `migrate_*` fixtures in `hort-server`, the
/// worker's schema-compat boot fixture, and [`shared_migrated_pool`].
/// Each of those grew its own `PgPool::connect(&url).await.ok()`, which
/// is the silent skip this module no longer performs: five independent
/// copies of it, none reachable from [`isolated_db_from`], which is why
/// the fix needed a second entry point rather than one.
///
/// The caller still owns the `DATABASE_URL` read and the `None` that
/// comes with it; this function is only ever handed a URL that exists.
pub async fn connect_or_panic(url: &str) -> PgPool {
    let opts = parse_or_panic(url);
    let target = connection_target(&opts);
    match PgPool::connect_with(opts).await {
        Ok(pool) => pool,
        Err(err) => panic!(
            "{}",
            unusable_database_message("connecting a pool", &target, &err)
        ),
    }
}

/// Parse `url` into connection options, panicking with a message that
/// withholds the value.
///
/// A malformed `DATABASE_URL` is a configuration error the operator has
/// to see; skipping on it hides a typo behind a green run for as long as
/// the typo lives.
fn parse_or_panic(url: &str) -> PgConnectOptions {
    match url.parse::<PgConnectOptions>() {
        Ok(opts) => opts,
        Err(err) => panic!(
            "{}",
            unusable_database_message(
                "parsing it as a Postgres connection URL",
                "<unparseable, value withheld>",
                &err
            )
        ),
    }
}

/// Create a uniquely-named database (derived from `base_url`: same
/// host/user/password, fresh dbname) and return a pool connected to it.
/// The DB is **empty** — the caller runs its own
/// `sqlx::migrate!().run()` on the returned pool.
///
/// ## It never returns `None`. It panics instead
///
/// Every call site in the workspace is `let url =
/// env::var("DATABASE_URL").ok()?;` immediately followed by this call,
/// so "not configured" is decided one level up and this function never
/// sees it. What is left is a database the operator declared and the
/// harness could not use — and flattening that into the same `None` the
/// caller uses for "no database" makes the caller early-return, which
/// libtest reports as `ok`. A test that did not run then claims it
/// passed, precisely when the server is unwell and the gate matters
/// most. Measured on the unfixed code against a closed port: 12,350
/// passed, 1 failed, 7 ignored — the one failure being the single test
/// in the workspace that hand-rolled `.expect()` on its own maintenance
/// connection.
///
/// The `Option` in the return type belongs to the caller, not to this
/// function: it is what keeps the `?` carrying the caller's `env::var`
/// skip compiling. `crates/hort-app/tests/db_gate_not_silent.rs` pins
/// the property this doc comment asserts.
///
/// ## What a transient blip costs
///
/// The per-database `PgPool::connect_with` below inherits sqlx's own
/// connect retry: `ConnectionRefused`, SQLSTATE `57P03`
/// (`cannot_connect_now` — the server is starting up or in recovery) and
/// `53300` (`too_many_connections`) are retried with exponential backoff
/// until `acquire_timeout`, 30 s by default, so a blip shorter than that
/// never reaches a panic. The maintenance connection is a bare
/// `PgConnection` and has no such retry — one refused connection fails
/// that test. The asymmetry is sqlx's, not this module's, and it is left
/// alone deliberately: a retry here would be a second retry policy
/// beside the migration loop below, and in the incident this hard
/// failure was written for — a seven-minute recovery — no retry length
/// would have changed the outcome.
pub async fn isolated_db_from(base_url: &str) -> Option<PgPool> {
    let opts = parse_or_panic(base_url);
    let target = connection_target(&opts);
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
    let mut admin = match PgConnection::connect_with(&opts.clone().database("postgres")).await {
        Ok(admin) => admin,
        Err(err) => panic!(
            "{}",
            unusable_database_message(
                "opening the `postgres` maintenance connection",
                &target,
                &err
            )
        ),
    };

    // Once per process, on the connection we already hold.
    sweep_stale_databases(&mut admin).await;

    if let Err(err) = admin
        .execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{db}\"")))
        .await
    {
        panic!(
            "{}",
            unusable_database_message("creating the per-test database", &target, &err)
        );
    }
    let _ = admin.close().await;

    let pool = match per_test_pool_options()
        .connect_with(opts.database(&db))
        .await
    {
        Ok(pool) => pool,
        Err(err) => panic!(
            "{}",
            unusable_database_message("connecting to the per-test database", &target, &err)
        ),
    };

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
/// Returns `None` only when `DATABASE_URL` is unset — the one condition
/// that means "this machine has no database", and the one the workspace
/// pre-push gate runs under. A target that is set but unreachable panics
/// through [`connect_or_panic`], as does a migration that fails after
/// retries: both are a configured database that did not work, and a test
/// that reports `ok` without having touched it is a false green, not a
/// skip. Unreachability here used to cost 30 s of `acquire_timeout` per
/// test and then report `ok` anyway.
pub async fn shared_migrated_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = connect_or_panic(&url).await;

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

/// Mark an artifact soft-deleted, the way `ArtifactRepository::delete`
/// does: `deleted_at` set, every other column untouched.
///
/// Lives here rather than per test file because four suites need it to
/// state the same property from different angles — that a reader of
/// `artifacts` either excludes deleted rows or declares why it does not
/// (`hort-app/tests/live_reads_exclude_deleted.rs`) — and a per-file copy
/// is how one of them ends up marking the row some *other* way and
/// asserting about a state production cannot reach.
///
/// Panics when no row matches: a test that soft-deletes nothing and then
/// asserts an absence passes for the wrong reason.
pub async fn soft_delete_artifact(pool: &PgPool, artifact_id: uuid::Uuid) {
    let affected = sqlx::query("UPDATE public.artifacts SET deleted_at = now() WHERE id = $1")
        .bind(artifact_id)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("soft-delete artifact {artifact_id}: {e}"))
        .rows_affected();
    assert_eq!(
        affected, 1,
        "soft_delete_artifact({artifact_id}) matched {affected} rows — the \
         artifact must exist, or the absence a caller then asserts proves \
         nothing"
    );
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

    use serial_test::serial;

    /// A [`DropCandidate`] whose every drop costs a fixed amount of time
    /// and returns a scripted verdict. Under
    /// `tokio::test(start_paused = true)` that time is virtual, so the
    /// budget loop is exercised against a drop far slower than any real
    /// one without the test taking any wall clock at all.
    struct SlowDrop {
        per_drop: Duration,
        /// Verdicts in order; the last one repeats once the script runs
        /// out, so "always times out" is a one-element script.
        script: Vec<DropVerdict>,
        seen: Vec<String>,
    }

    impl SlowDrop {
        fn taking(per_drop: Duration) -> Self {
            Self {
                per_drop,
                script: vec![DropVerdict::Dropped],
                seen: Vec::new(),
            }
        }

        fn returning(mut self, script: Vec<DropVerdict>) -> Self {
            assert!(!script.is_empty(), "the script's last verdict repeats");
            self.script = script;
            self
        }
    }

    impl DropCandidate for SlowDrop {
        async fn drop_candidate(&mut self, name: &str) -> DropVerdict {
            let verdict = self.script[self.seen.len().min(self.script.len() - 1)];
            self.seen.push(name.to_string());
            tokio::time::sleep(self.per_drop).await;
            verdict
        }
    }

    /// The per-drop cost the server imposes when it cancels one: the
    /// `statement_timeout`, to the millisecond, measured on a real
    /// server parked on `IPC/CheckpointStart`.
    const CANCELLED_DROP: Duration = Duration::from_millis(DROP_STATEMENT_TIMEOUT_MS);

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
        let mut dropper =
            SlowDrop::taking(Duration::from_millis(10)).returning(vec![DropVerdict::Skipped]);

        let outcome = drop_within_budget(candidates(3), SWEEP_BUDGET, &mut dropper).await;

        assert_eq!(outcome.attempted, 3, "{outcome:?}");
        assert_eq!(outcome.dropped, 0, "{outcome:?}");
        assert_eq!(outcome.timed_out, 0, "{outcome:?}");
        assert!(
            !outcome.gave_up_on_timeouts,
            "a candidate-local failure says nothing about the server: {outcome:?}"
        );
        assert!(
            !outcome.exhausted_budget,
            "a skipped candidate is not a spent budget"
        );
    }

    // ---- The give-up rule: a sweep that cannot drop must not keep
    // paying the per-drop ceiling to find that out again. Each cancelled
    // drop costs the full `statement_timeout` AND queues another forced
    // immediate checkpoint behind the backlog it is waiting on, so the
    // loop is not merely wasting its own budget, it is lengthening the
    // queue. Reproduced against a real server: four candidates, four
    // SQLSTATE 57014 cancellations at exactly 1500 ms each, 6002 ms
    // spent, nothing dropped.

    #[tokio::test(start_paused = true)]
    async fn a_server_that_cannot_finish_a_drop_does_not_get_the_whole_budget() {
        let mut dropper = SlowDrop::taking(CANCELLED_DROP).returning(vec![DropVerdict::OutOfTime]);
        let started = Instant::now();

        let outcome = drop_within_budget(candidates(40), SWEEP_BUDGET, &mut dropper).await;

        assert_eq!(
            outcome.attempted, TIMEOUTS_BEFORE_GIVING_UP,
            "the loop must stop at the give-up rule, not at the budget: {outcome:?}"
        );
        assert_eq!(outcome.timed_out, TIMEOUTS_BEFORE_GIVING_UP, "{outcome:?}");
        assert_eq!(outcome.dropped, 0, "{outcome:?}");
        assert!(outcome.gave_up_on_timeouts, "{outcome:?}");
        assert!(
            !outcome.exhausted_budget,
            "giving up has to leave budget behind, or it is just a slower \
             way of spending it: {outcome:?}"
        );
        assert!(
            started.elapsed() < SWEEP_BUDGET,
            "the sweep must hand the rest of its budget back, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn one_cancelled_drop_does_not_abandon_a_sweep_that_is_working() {
        // A single cancellation can be a candidate that happened to
        // arrive while a checkpoint was already running. Only a second
        // one with no drop completing in between is evidence about the
        // server.
        let mut dropper = SlowDrop::taking(Duration::from_millis(100)).returning(vec![
            DropVerdict::Dropped,
            DropVerdict::OutOfTime,
            DropVerdict::Dropped,
            DropVerdict::OutOfTime,
            DropVerdict::Dropped,
        ]);

        let outcome = drop_within_budget(candidates(5), SWEEP_BUDGET, &mut dropper).await;

        assert_eq!(outcome.attempted, 5, "{outcome:?}");
        assert_eq!(outcome.dropped, 3, "{outcome:?}");
        assert_eq!(outcome.timed_out, 2, "{outcome:?}");
        assert!(
            !outcome.gave_up_on_timeouts,
            "a completed drop resets the count: {outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_give_up_count_resets_only_on_a_completed_drop() {
        // A skip is cheap and local — it is neither evidence that the
        // server is healthy nor evidence that it is not — so it must
        // neither trip the rule nor clear it.
        let mut dropper = SlowDrop::taking(Duration::from_millis(10)).returning(vec![
            DropVerdict::OutOfTime,
            DropVerdict::Skipped,
            DropVerdict::Skipped,
            DropVerdict::OutOfTime,
            DropVerdict::Dropped,
        ]);

        let outcome = drop_within_budget(candidates(5), SWEEP_BUDGET, &mut dropper).await;

        assert_eq!(
            outcome.attempted, 4,
            "the second cancellation must stop the loop even with skips \
             between the two: {outcome:?}"
        );
        assert!(outcome.gave_up_on_timeouts, "{outcome:?}");
        assert_eq!(outcome.dropped, 0, "{outcome:?}");
    }

    /// A `DatabaseError` carrying nothing but a SQLSTATE, so the
    /// classification can be exercised without a server. The real
    /// counterpart is pinned against one by
    /// `a_statement_the_server_cancels_really_does_carry_57014`.
    #[derive(Debug)]
    struct SqlState(&'static str);

    impl std::fmt::Display for SqlState {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "SQLSTATE {}", self.0)
        }
    }

    impl std::error::Error for SqlState {}

    impl sqlx::error::DatabaseError for SqlState {
        fn message(&self) -> &str {
            "synthetic"
        }
        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(std::borrow::Cow::Borrowed(self.0))
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn db_error(sqlstate: &'static str) -> sqlx::Error {
        sqlx::Error::Database(Box::new(SqlState(sqlstate)))
    }

    #[test]
    fn only_the_servers_own_clock_counts_towards_giving_up() {
        assert_eq!(verdict_for(&db_error("57014")), DropVerdict::OutOfTime);
        // 55P03 is `lock_not_available` — a peer sweeper holds this
        // candidate's object lock and is dropping it. Local to the
        // candidate, bounded by DROP_LOCK_TIMEOUT_MS, and work that is
        // being done anyway.
        assert_eq!(verdict_for(&db_error("55P03")), DropVerdict::Skipped);
        // 55006 is `object_in_use` — somebody connected since the
        // candidate query. The oldest skip path there is.
        assert_eq!(verdict_for(&db_error("55006")), DropVerdict::Skipped);
        // 42501 is `insufficient_privilege`. Permanent, but still not a
        // statement about the next candidate.
        assert_eq!(verdict_for(&db_error("42501")), DropVerdict::Skipped);
        assert_eq!(verdict_for(&sqlx::Error::PoolClosed), DropVerdict::Skipped);
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
            timed_out: 0,
            exhausted_budget: false,
            gave_up_on_timeouts: false,
        };
        assert_eq!(sweep_warning(&outcome, Duration::from_millis(900)), None);
    }

    #[test]
    fn a_sweep_that_ran_out_of_budget_carries_the_numbers_that_explain_it() {
        let outcome = SweepOutcome {
            candidates: 1251,
            attempted: 37,
            dropped: 36,
            timed_out: 1,
            exhausted_budget: true,
            gave_up_on_timeouts: false,
        };
        let warning = sweep_warning(&outcome, Duration::from_millis(3040))
            .expect("an exhausted budget must be reported");
        for fragment in ["1251", "37", "36", "3040"] {
            assert!(
                warning.contains(fragment),
                "warning must carry {fragment}: {warning}"
            );
        }
        assert!(
            !warning.contains("gave up"),
            "a sweep that spent its budget did not give up: {warning}"
        );
    }

    #[test]
    fn a_sweep_that_gave_up_says_so_and_says_what_to_look_at() {
        // The state the field reported as `880 candidates, 4 attempted,
        // 0 dropped`: without this line the only symptom is a test
        // database population that quietly stops shrinking.
        let outcome = SweepOutcome {
            candidates: 880,
            attempted: 2,
            dropped: 0,
            timed_out: 2,
            exhausted_budget: false,
            gave_up_on_timeouts: true,
        };
        let warning = sweep_warning(&outcome, Duration::from_millis(3001))
            .expect("a sweep that gave up must be reported");
        for fragment in ["880", "gave up", "checkpoint", "3001"] {
            assert!(
                warning.contains(fragment),
                "warning must carry {fragment}: {warning}"
            );
        }
        assert!(
            !warning.contains("budget"),
            "the budget was not the reason and naming it sends the reader \
             after the wrong thing: {warning}"
        );
    }

    // ---- The age gate and what stands beside it.
    //
    // `STALE_AFTER_SECS` is a safety property: it is the only thing
    // between a database and the sweep during the window in which the
    // database exists and nothing is connected to it yet. These two pin
    // both halves of the argument that lets it be two minutes rather
    // than ten — if either fails, the window the short gate relies on
    // somebody else covering has been reopened.

    #[test]
    fn the_per_test_pool_publishes_its_ownership_for_as_long_as_it_lives() {
        assert!(
            per_test_pool_options().get_min_connections() >= 1,
            "the sweep reads `no backend in pg_stat_activity` as `the owning pool is \
             gone`. With `min_connections = 0` an idle pool stops publishing its \
             ownership while its test is still running, and the only thing left between \
             that database and a sweep is STALE_AFTER_SECS — which is then far too short \
             for the job."
        );
    }

    #[test]
    fn the_age_gate_outlasts_the_create_to_first_connect_window() {
        // The window the gate covers runs from `CREATE DATABASE` to the
        // first connection of the pool built next, and sqlx's
        // `acquire_timeout` is its ceiling: the pool's first connect
        // retries `ConnectionRefused` / 57P03 / 53300 with backoff until
        // then, and `isolated_db_from` panics after. A gate that does
        // not comfortably exceed that ceiling can hand a sibling's
        // not-yet-connected database to the sweep.
        let ceiling = per_test_pool_options().get_acquire_timeout();
        assert!(
            Duration::from_secs(STALE_AFTER_SECS) >= ceiling * 4,
            "STALE_AFTER_SECS ({STALE_AFTER_SECS}s) must stay several times sqlx's \
             acquire_timeout ({ceiling:?}), which bounds how long a database can exist \
             with nobody connected to it and still be wanted"
        );
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

    // ---- The skip contract: unset is a skip, unusable is a failure.
    //
    // These run DB-free. The "unusable" side uses a host under the
    // reserved `.invalid` TLD (RFC 2606 guarantees it never resolves),
    // which fails at name resolution rather than at TCP connect. That
    // matters for timing: sqlx's pool retries `ConnectionRefused` with
    // backoff until its 30 s `acquire_timeout`, but returns any other
    // connect error immediately — so a closed port would make these
    // tests cost 30 s each and an unresolvable host costs milliseconds.
    //
    // They call `isolated_db_from` and `connect_or_panic`, so they carry
    // `#[serial(hort_pg_db)]` like every other caller of those. Nothing
    // about *these four* needs it — name resolution fails before a
    // socket is opened, so none of the cluster-global work the key
    // exists for (`CREATE ROLE`, `CREATE`/`DROP DATABASE`,
    // `pg_stat_activity`) is ever reached. The key is here because the
    // rule has no exemptions: `crates/hort-app/tests/
    // db_tests_are_serialized.rs` reports every test that calls one of
    // these entry points, and an exception carved into it would be an
    // allow-list the next unkeyed test could hide in. The cost is a
    // failed DNS lookup's worth of queueing.

    /// The URL shape these tests feed the helpers: syntactically valid,
    /// unreachable by construction, and carrying a password so the
    /// redaction assertion below has something to catch.
    const UNREACHABLE_URL: &str = "postgres://probe:hunter2@hort-db-gate.invalid:5432/hort";

    /// Run `fut` on a fresh current-thread runtime and return the panic
    /// message it produced.
    ///
    /// `#[should_panic(expected = …)]` can only assert a substring is
    /// present; the credential test has to assert one is *absent*, which
    /// needs the message itself.
    fn panic_message_of<F>(make: F) -> String
    where
        F: FnOnce() + std::panic::UnwindSafe,
    {
        let payload = std::panic::catch_unwind(make).expect_err("expected a panic");
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_default()
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(fut)
    }

    #[test]
    #[serial(hort_pg_db)]
    fn isolated_db_from_fails_loudly_when_the_configured_server_is_unreachable() {
        let message = panic_message_of(|| {
            let _ = block_on(isolated_db_from(UNREACHABLE_URL));
        });
        assert!(
            message.contains("hard failure, not a skip"),
            "a configured-but-unreachable target must not be flattened into a \
             skip; got: {message}"
        );
        assert!(
            message.contains("maintenance connection"),
            "the message must name the stage that failed: {message}"
        );
    }

    #[test]
    #[serial(hort_pg_db)]
    fn connect_or_panic_fails_loudly_when_the_configured_server_is_unreachable() {
        let message = panic_message_of(|| {
            let _ = block_on(connect_or_panic(UNREACHABLE_URL));
        });
        assert!(
            message.contains("hard failure, not a skip"),
            "the shared-target connect must not be flattened into a skip; got: {message}"
        );
        assert!(
            message.contains("connecting a pool"),
            "the message must name the stage that failed: {message}"
        );
    }

    #[test]
    #[serial(hort_pg_db)]
    fn an_unparseable_database_url_fails_loudly_and_withholds_the_value() {
        let message = panic_message_of(|| {
            let _ = block_on(isolated_db_from(
                "postgres://probe:hunter2@host:notaport/db",
            ));
        });
        assert!(
            message.contains("parsing it"),
            "a malformed DATABASE_URL is a configuration error the operator has \
             to see, not a skip; got: {message}"
        );
        assert!(
            !message.contains("hunter2"),
            "the panic lands in a CI log and must not carry the password: {message}"
        );
    }

    #[test]
    #[serial(hort_pg_db)]
    fn the_unreachable_panic_withholds_the_password() {
        let message = panic_message_of(|| {
            let _ = block_on(isolated_db_from(UNREACHABLE_URL));
        });
        assert!(
            !message.contains("hunter2"),
            "the panic lands in a CI log and must not carry the password: {message}"
        );
        assert!(
            message.contains("hort-db-gate.invalid:5432"),
            "host:port is the diagnostic part and must survive redaction: {message}"
        );
    }

    #[test]
    fn the_failure_message_names_the_stage_the_target_and_the_way_out() {
        let message = unusable_database_message("opening a connection", "db.example:5432", &"boom");
        assert!(message.contains("opening a connection"), "{message}");
        assert!(message.contains("db.example:5432"), "{message}");
        assert!(message.contains("boom"), "{message}");
        assert!(
            message.contains("unset DATABASE_URL"),
            "the message must say how to run the suite DB-free: {message}"
        );
    }

    #[test]
    fn the_target_rendering_carries_no_credentials() {
        let opts: PgConnectOptions = UNREACHABLE_URL.parse().expect("URL parses");
        let target = connection_target(&opts);
        assert_eq!(target, "hort-db-gate.invalid:5432");
        assert!(!target.contains("hunter2"), "{target}");
        assert!(!target.contains("probe"), "{target}");
    }

    // ---- Against a real server.
    //
    // These skip on the one condition the whole module skips on —
    // `DATABASE_URL` unset — and are hard failures from there.

    /// A maintenance connection to `postgres` on the configured target,
    /// or `None` when no database is configured.
    async fn maybe_admin() -> Option<PgConnection> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let opts = parse_or_panic(&url).database("postgres");
        let target = connection_target(&opts);
        match PgConnection::connect_with(&opts).await {
            Ok(conn) => Some(conn),
            Err(err) => panic!(
                "{}",
                unusable_database_message("opening the maintenance connection", &target, &err)
            ),
        }
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_database_somebody_is_connected_to_is_never_a_candidate() {
        let Some(mut admin) = maybe_admin().await else {
            return;
        };
        let url = std::env::var("DATABASE_URL").expect("checked by maybe_admin");
        let pool = isolated_db_from(&url).await.expect("a per-test database");
        let mine: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&pool)
            .await
            .expect("the database names itself");

        // A cutoff in the far future opens the age gate completely, so
        // the only thing that can keep this database out of the list is
        // the live-connection check — which is the point. The pool is
        // idle here, not querying: `per_test_pool_options` is why it is
        // still connected.
        let far_future = now_unix_secs() + 60 * 60 * 24 * 365;
        let listed: Vec<String> =
            sqlx::query_scalar(sqlx::AssertSqlSafe(candidate_query(far_future)))
                .fetch_all(&mut admin)
                .await
                .expect("the candidate query runs");

        assert!(
            !listed.contains(&mine),
            "the sweep offered up a database with a live pool on it ({mine}); \
             dropping one out from under a running sibling is worse than any \
             number of leaked databases"
        );

        // And once the owner is gone it *is* reclaimable — otherwise the
        // assertion above would also pass on a query that returns
        // nothing at all. The backend leaves `pg_stat_activity` when the
        // server-side process exits, which trails the client's close by
        // a little, so this waits rather than sampling once.
        pool.close().await;
        let mut reclaimable = false;
        for _ in 0..100 {
            let listed_after: Vec<String> =
                sqlx::query_scalar(sqlx::AssertSqlSafe(candidate_query(far_future)))
                    .fetch_all(&mut admin)
                    .await
                    .expect("the candidate query runs");
            if listed_after.contains(&mine) {
                reclaimable = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            reclaimable,
            "a database whose pool has closed must become a candidate, or the \
             assertion above proves nothing"
        );

        let _ = admin
            .execute(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS \"{mine}\""
            )))
            .await;
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_age_gate_keeps_a_young_unconnected_database_out_of_the_list() {
        // The window `STALE_AFTER_SECS` exists for, reproduced: a
        // database that exists and has nobody connected to it yet.
        let Some(mut admin) = maybe_admin().await else {
            return;
        };
        let young = format!(
            "hort_test_{}_{}",
            now_unix_secs(),
            uuid::Uuid::new_v4().simple()
        );
        admin
            .execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{young}\"")))
            .await
            .expect("CREATE DATABASE");

        let cutoff = now_unix_secs().saturating_sub(STALE_AFTER_SECS);
        let listed: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(candidate_query(cutoff)))
            .fetch_all(&mut admin)
            .await
            .expect("the candidate query runs");

        let offered = listed.contains(&young);
        let _ = admin
            .execute(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS \"{young}\""
            )))
            .await;
        assert!(
            !offered,
            "a database created a moment ago, with nobody connected yet, is \
             exactly what the age gate is for"
        );
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_statement_the_server_cancels_really_does_carry_57014() {
        // `verdict_for` reads one SQLSTATE and the give-up rule hangs
        // off it. The DB-free test asserts the mapping; this one
        // asserts the server still produces the code being mapped.
        let Some(mut admin) = maybe_admin().await else {
            return;
        };
        admin
            .execute(sqlx::AssertSqlSafe("SET statement_timeout = 50"))
            .await
            .expect("SET statement_timeout");
        let err = admin
            .execute(sqlx::AssertSqlSafe("SELECT pg_sleep(5)"))
            .await
            .expect_err("a 5-second sleep under a 50 ms statement_timeout is cancelled");
        let _ = admin
            .execute(sqlx::AssertSqlSafe("RESET statement_timeout"))
            .await;

        assert_eq!(
            verdict_for(&err),
            DropVerdict::OutOfTime,
            "the sweep stops on the server's own clock, so the code it reads \
             has to be the code the server sends: {err}"
        );
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn an_interrupted_drop_is_offered_again_before_any_untouched_candidate() {
        // A cancelled drop leaves `datconnlimit = -2` behind, and
        // re-dropping is an ordinary drop rather than a cheap finish
        // (measured: 69–111 ms against 59–82 ms for never-cancelled
        // drops on the same idle server). So these have to be taken
        // first, or `ORDER BY random()` over hundreds of candidates
        // leaves a growing population nothing ever revisits.
        let Some(mut admin) = maybe_admin().await else {
            return;
        };
        let old_epoch = now_unix_secs().saturating_sub(STALE_AFTER_SECS * 10);
        let mut made = Vec::new();
        for _ in 0..2 {
            let name = format!("hort_test_{old_epoch}_{}", uuid::Uuid::new_v4().simple());
            admin
                .execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
                .await
                .expect("CREATE DATABASE");
            made.push(name);
        }
        let (condemned, untouched) = (made[0].clone(), made[1].clone());

        // PostgreSQL 16 commits the invalid marker before the
        // destructive phase, so cancelling the drop mid-checkpoint
        // leaves it set. The deadline escalates because the phase
        // before the marker is short but not instantaneous.
        let mut invalidated = false;
        let mut timeout_ms = 5u64;
        for _ in 0..8 {
            let _ = admin
                .execute(sqlx::AssertSqlSafe(format!(
                    "SET statement_timeout = {timeout_ms}"
                )))
                .await;
            let _ = admin
                .execute(sqlx::AssertSqlSafe(format!(
                    "DROP DATABASE IF EXISTS \"{condemned}\""
                )))
                .await;
            let _ = admin
                .execute(sqlx::AssertSqlSafe("RESET statement_timeout"))
                .await;
            let marker: Option<i32> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT datconnlimit FROM pg_database WHERE datname = '{condemned}'"
            )))
            .fetch_optional(&mut admin)
            .await
            .expect("pg_database is readable");
            match marker {
                Some(DATCONNLIMIT_INVALID_DB) => {
                    invalidated = true;
                    break;
                }
                // Cancelled before the marker — the phase ahead of it is
                // short but not instantaneous. Give the next attempt
                // longer.
                Some(_) => timeout_ms *= 4,
                // The drop finished inside the deadline. Make another
                // candidate and keep the leash where it is.
                None => {
                    admin
                        .execute(sqlx::AssertSqlSafe(format!(
                            "CREATE DATABASE \"{condemned}\""
                        )))
                        .await
                        .expect("CREATE DATABASE");
                }
            }
        }
        assert!(
            invalidated,
            "could not cancel a DROP DATABASE past the invalid marker, so the \
             ordering this test exists for cannot be exercised"
        );

        let listed: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(candidate_query(
            now_unix_secs().saturating_sub(STALE_AFTER_SECS),
        )))
        .fetch_all(&mut admin)
        .await
        .expect("the candidate query runs");

        let rank = |name: &String| {
            listed
                .iter()
                .position(|n| n == name)
                .unwrap_or_else(|| panic!("{name} must be a candidate; got {listed:?}"))
        };
        let (condemned_at, untouched_at) = (rank(&condemned), rank(&untouched));

        for name in &made {
            let _ = admin
                .execute(sqlx::AssertSqlSafe("SET statement_timeout = 0"))
                .await;
            let _ = admin
                .execute(sqlx::AssertSqlSafe(format!(
                    "DROP DATABASE IF EXISTS \"{name}\""
                )))
                .await;
        }
        assert!(
            condemned_at < untouched_at,
            "a database an earlier sweep condemned must be offered before one \
             nothing has touched ({condemned} at {condemned_at}, {untouched} at \
             {untouched_at})"
        );
    }
}
