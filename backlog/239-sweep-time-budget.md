# 239 — The stale-database sweep needs a time budget, not a count cap

**Issue:** #298 · **Branch:** `agent/298-sweep-time-budget`
**Governing decisions:** ADR 0019 (DB test serial isolation — re-justified, not
weakened) · #37 (the accumulation failure whose fix introduced the sweeper) ·
#236 (the measurements this item rests on).

## Why

#236 refuted its own leading hypothesis in three configurations — the sweep
burst does **not** starve a concurrent acquirer; a process running the full
acquisition path through a 242-second sweep of 600 databases showed no
degradation at all, 90 of 90 acquires under a millisecond. The behaviour change
was therefore deliberately not made, and this item carries what the
measurements say instead.

Two facts make the population load-bearing anyway:

**The sweep blocks the run it belongs to.** It runs inside the first DB-backed
test of the process, which holds the crate-wide `#[serial(hort_pg_db)]` key for
its whole duration. At 1,251 candidates that was a 77-second stall that pushed
three unrelated tests past libtest's 60-second threshold.

**The population drives dynamic-shared-memory pressure, and that is what
crashed the cluster.** Measured 2026-09-26: at 634 test databases `/dev/shm`
stood at 60 of 63 MB. One DSM request is 32 MB, `autovacuum_max_workers` is 3
and `max_parallel_workers` is 8 — so two concurrent allocations do not fit, and
a parallel `ANALYZE` on a test database's catalogs segfaulted the backend,
taking the whole cluster into a seven-minute recovery in which every agent's
connection failed.

**The container's `/dev/shm` ceiling is the cause and is not in scope here** —
it is a platform-side `--shm-size` change, and the same measurement shows the
baseline is 44 MB with *zero* test databases, so raising the ceiling is the fix
and reducing the population is not a substitute for it. But the population is
the multiplier: it decides how many autovacuum workers are plausibly parallel
at once.

## What the measurements say about the shape

**A count cap is the wrong instrument.** #236 proposed "at most ~50 drops per
sweep", sized against a model of hundreds of cheap catalog statements. The
model is wrong:

- Every `DROP DATABASE` requests an **immediate, waited-on checkpoint**.
  Evidence: `checkpoints_req` rose by exactly +1251 for 1251 drops, second by
  second, while `CREATE DATABASE` moved the same counter by +1 across the rest
  of the run.
- The per-drop cost is **not bounded by anything the harness controls**:
  60–80 ms against an idle server, **136 s** for a single `DROP DATABASE` with
  one concurrent writer (`IPC/CheckpointDone`), **73 s** with a concurrent
  sweep (`Lock/object` — `DROP DATABASE` takes an exclusive lock on the
  database object, so concurrent sweeps serialise against each other).

A cap of 50 is therefore **over an hour** in the worst measured case, with the
serial key held throughout. The bound that matches the mechanism is a **wall-
clock budget**: stop sweeping after N seconds. A count cap *in addition* is
reasonable, but it is not the load-bearing one.

**Throughput carries it.** 36 processes per workspace run reach the sweep (34
integration-test binaries plus two lib unittest binaries), and one run against
a purged cluster creates 429 databases. There is ample aggregate capacity to
keep up with the creation rate even with a per-sweep bound.

## The ordering is a condition, not a preference

Lowering `STALE_AFTER_SECS` from 3600 to ~600 is right: the age gate only has
to cover the window between `CREATE DATABASE` and the first connection
appearing in `pg_stat_activity` — milliseconds — and the live-connection check
is the stronger test for everything after.

**But it must not land before a working cost bound.** A ten-minute window makes
a run's own earlier databases candidates *during the same run*, which raises
the per-sweep candidate count in the steady state and makes the stall more
frequent, not less. The two halves are ordered.

## The instrumentation is invisible (#236 FLAG-1)

`sweep_stale_databases` now reports `candidates`, `dropped` and `elapsed_ms` —
as `tracing::debug!`, and **no test binary in the workspace installs a
subscriber**. A `tracing` event with no subscriber is a no-op, so the number
exists for anyone who looks with `RUST_LOG=hort_adapters_postgres=debug` and is
unreadable from a plain `cargo test` — which is exactly where "1,251 databases
went unnoticed" happened.

Decide, with an argument: a `tracing_subscriber` behind `RUST_LOG` in the
DB-test path; an `eprintln!` of the same summary (visible only under
`--nocapture`); or leave it. The third is admissible, but then say what carries
the visibility instead.

## Read first

- `crates/hort-adapters-postgres/src/test_support.rs` — the whole module doc,
  which already records the cost model and the measurements; `STALE_AFTER_SECS`,
  `SWEPT`, `sweep_stale_databases`, `isolated_db_from`.
- `crates/hort-adapters-postgres/src/lib.rs` — `classify_migrate_failure`, whose
  hint carries the pool-size refutation.

## Acceptance

- No sweep holds the serial key longer than a named, argued wall-clock budget —
  with a test that demonstrates it against an **artificially slowed drop**, not
  only against a fast one. A budget that is only ever tested on a fast path is
  not tested.
- After one workspace run followed by a second, `hort_test_*` settles at
  roughly one run's worth instead of climbing monotonically. Measured, not
  argued.
- The ordering is honoured: the cost bound stands before `STALE_AFTER_SECS`
  drops.
- The visibility question is decided and argued.
- The module doc says what the new bound guarantees — **and what it does not**.
  In particular it does not make the cluster safe on its own; the `/dev/shm`
  ceiling is the cause and lives outside this repository.
- Gate green, `#[serial(hort_pg_db)]` on every test that acquires a connection.

## Explicitly not in this item

- No `--shm-size` change (platform side, outside this repository).
- No drop-on-teardown guard — 59 files call `isolated_db_from`, and the
  trade-off has now been re-confirmed twice.
- No change to pool sizing. Refuted twice over, and the measurement sits in the
  code beside the decision.
- No relaxation of `#[serial(hort_pg_db)]`.
