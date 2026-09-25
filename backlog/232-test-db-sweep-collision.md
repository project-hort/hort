# 232 — The stale-database sweep collides with the run it is part of

**Issue:** #236 · **Branch:** `agent/236-test-db-sweep-collision`
**Governing decisions:** ADR 0019 (DB test serial isolation — re-justified
here, not weakened) · #37 (the accumulation failure whose fix introduced the
sweeper).

## Why

`cargo test --workspace` intermittently fails with a connection-acquisition
timeout in an arbitrary `hort-adapters-postgres` test, on a tree that has
nothing to do with the database. Both observed cases already carried
`#[serial(hort_pg_db)]`, so this is not the missing-serial-guard class, and
both passed on re-run. Each occurrence costs a full re-run of the suite.

**Connection-limit exhaustion is refuted, by measurement.** A full run sampled
`pg_stat_activity` every two seconds: peak concurrent client backends **10**
against 97 usable, 1–4 for the great majority of the run, peak 5 distinct test
databases in use at once. sqlx pools are lazy (`min_connections = 0`) and
`cargo test` runs test binaries sequentially. A fix aimed at pool sizing would
change nothing.

**The leading hypothesis is the sweep itself.** `sweep_stale_databases` runs
once per process, on the first `isolated_db_from` call, and issues its
`DROP DATABASE` statements **serially in one burst** while sibling threads in
the same binary proceed to `CREATE DATABASE` and connect. Hundreds of
catalog-level DDL statements against one server is a coherent mechanism for a
30-second acquire timeout on a server with 92 free slots: the wait is not for a
slot, it is for a server busy with catalog work.

## Measured 2026-09-25, and it is worse than the issue recorded

The sandbox cluster was reset to **zero** test databases earlier the same day.
By early afternoon, after roughly four workspace runs:

```
hort_test_* databases   1251
total size              11 GB
created in one hour     1197
sweep-eligible now      1251  (all of them)
```

Two things follow, and both change the shape of the work:

1. **A run costs ~300 databases, not the ~50 this issue recorded on
   2026-09-11.** The suite has grown; the figure in the issue is stale.
2. **The reproduction is already armed.** Every one of the 1251 is older than
   `STALE_AFTER_SECS`, has no live connection, and is therefore a sweep
   candidate. The next test process to call `isolated_db_from` will attempt
   **1251 serial `DROP DATABASE` statements in one burst** — the hypothesised
   mechanism, at a scale above the 1091 databases that produced #37's
   *"every connection attempt inside that window failed"*.

   **Do not reset the cluster before you have observed this.** Measure first;
   the seeding step the issue describes is unnecessary because the server is
   already in the state it asks you to construct.

## Read first

- `crates/hort-adapters-postgres/src/test_support.rs` — the whole module:
  `STALE_AFTER_SECS`, `SWEPT`, `sweep_stale_databases`, `isolated_db_from`,
  `shared_migrated_pool`, and the module docstring's accumulation claim.
- `CLAUDE.md` — *DB-backed test isolation (parallel-safety contract)*.
- `.gitlab-ci.yml` — the `test:integration` job, to confirm what CI actually
  runs (plain `cargo test`, not `nextest`).

## Scope

### 1. Confirm the mechanism before changing behaviour

Instrument `sweep_stale_databases` with its candidate count and elapsed time at
`debug!` — a number the harness never reports today, which is why 1251
databases accumulated unnoticed. Then run the suite against the cluster as it
stands and record whether an acquire timeout falls inside the sweep burst.

If it does not reproduce, **stop and record the negative result** rather than
proceeding on the strength of a plausible story. The refutation of the
pool-size hypothesis stands either way.

### 2. Make the sweep stop colliding with the run it is part of

Both changes inside `test_support.rs`:

- **Bound the per-process batch** to a fixed number of drops per sweep (order
  of 50). A workspace run has many processes, so total throughput is unchanged,
  but no single burst can be a thousand statements long. This is the change
  that addresses the mechanism directly.
- **Shorten `STALE_AFTER_SECS` so a run can clean up after itself.** The
  one-hour gate exists to protect a concurrently-running sibling's fresh
  database — but the sweep *already* skips any candidate with a live connection
  in `pg_stat_activity`, so the age gate only covers the window between
  `CREATE DATABASE` and the first connection, which is milliseconds. Ten
  minutes is ample and lets each run reclaim the previous one's databases.

Correct the module docstring's "bounds accumulation to roughly one run's
worth" — the measurement contradicts it as written.

**Do not add a drop-on-teardown guard.** The module considered and rejected it;
58 files call `isolated_db_from` today, so the cost has only grown, and the two
changes above address the mechanism without it.

### 3. The pool sizing is explicitly not changed

Setting `max_connections` on the test pools is the fix this issue originally
proposed, and it is now known to be aimed at a non-cause. Leaving it alone is
the decision — record the measurement as the reason, so a future reader is not
tempted.

### 4. The stale parallel-safety rationale in `CLAUDE.md`

The *DB-backed test isolation* section says the suites "run in parallel against
one shared database/backend with **no per-test isolation**". That is half true,
and the false half is load-bearing, because the paragraph is the stated
justification for a mandatory blocking review check.

The harness has two modes: `isolated_db_from` (a fresh database per test, **58
files**) and `shared_migrated_pool` (the shared target, for tests that
deliberately exercise shared-DB behaviour, **5 files**). The paragraph
describes the five-file mode as though it were the whole harness.

The `#[serial(hort_pg_db)]` rule is still right, for a narrower reason that
must be written down instead:

- on the **shared** path the original rationale holds unchanged;
- on the **isolated** path a per-test database does *not* isolate
  cluster-global work — `CREATE ROLE`, `pg_stat_activity` probes, and the
  shared catalogs the sweeper touches are server-wide.

Name both helpers so a reader can tell which mode a test is in. Verify the two
file counts yourself rather than copying them; they are from this item's own
grep and the tree moves.

## Acceptance

- The mechanism is reproduced under instrumentation, or the negative result is
  recorded and the item stops at that.
- A sweep reports its candidate count and elapsed time, so a future
  accumulation is visible before it becomes a flake.
- No single sweep issues an unbounded run of `DROP DATABASE`.
- After one workspace run followed by a second, the `hort_test_*` count settles
  at roughly one run's worth instead of climbing monotonically.
- `CLAUDE.md` names both harness modes and justifies the `#[serial(hort_pg_db)]`
  rule from cluster-global scope, not from an absence of isolation that no
  longer describes 58 of the 63 call sites.
- `max_connections` on the test pools is unchanged, with the measurement
  recorded as the reason.

## Explicitly not in this item

No production code. No migrations. No relaxation of the `#[serial(hort_pg_db)]`
requirement — ADR 0019 stands. No drop-on-teardown guard.
