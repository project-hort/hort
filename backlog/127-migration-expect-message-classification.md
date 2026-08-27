# 127 — A pool timeout in test setup must not claim the migrations failed

Issue: #183.

## Why

Twice in one day — the cockpit's during #175 unit 124, and mine while gating
`v0.11.0-beta.7` — a diagnosis had to reason its way past a panic message that
asserted the opposite of what happened:

```
panicked at crates/hort-adapters-postgres/tests/scanner_registry_repository.rs:44:10:
migrations run cleanly against the test DB: Execute(PoolTimedOut)
```

`PoolTimedOut` means no connection could be acquired within the pool's
timeout. The migrations were never reached. But the message names them as the
subject, so the reader's first hypothesis is a broken migration — the single
most expensive hypothesis to hold mid-release.

## What the investigation established — build on this, do not re-derive

**The call-site `.expect()` is load-bearing by design, and must stay.**
`isolated_db_from()` (`crates/hort-adapters-postgres/src/test_support.rs`)
already runs the migration set with a bounded retry, and on persistent failure
deliberately returns the pool anyway. Its own comment states why:

> On persistent failure the pool is still returned: the call site's own
> `sqlx::migrate!().run()` then runs (a no-op once migrated; otherwise it
> surfaces the real error via its `.expect`, so a genuine migration bug is
> never masked into a silent skip).

So this item is **not** "remove the expect" and **not** "move migration into
the helper". Both are already decided the other way. The defect is the
message's wording: it claims a subject the error may not have.

**The shape is workspace-wide.** The identical string
`expect("migrations run cleanly against the test DB")` appears at **46 sites**
across 46 files — inline `#[cfg(test)]` modules in `hort-adapters-postgres`,
its `tests/` targets, plus `crates/hort-server/{src/cli/verify_event_chain.rs,
tests/exchange_cap_derivation_e2e.rs, tests/task_use_case_enqueue_real_db.rs}`.
Fixing one site leaves 45 that will mislead the next reader.

## What to do

Add one helper to `crates/hort-adapters-postgres/src/test_support.rs` that
migrates and **classifies the failure at the point it happens**, and route all
46 sites through it.

- On `sqlx::migrate::MigrateError::Execute(sqlx::Error::PoolTimedOut)` — and
  any other acquisition-shaped error — panic with a message naming
  **connection acquisition under contention**, not migrations. Say what the
  reader should check: another `cargo test` against the same server, other
  DB-backed targets, or the Postgres connection limit.
- On every other error, keep the present meaning: the migrations genuinely
  failed, and the existing message is accurate there.
- Preserve the underlying error in both branches. A classification that
  discards the cause trades one bad diagnosis for another.

Collapsing 46 duplicated call sites into one helper also serves the
duplication gate; that is a side benefit, not the goal.

## Scope boundaries

- **Not an isolation change.** `CLAUDE.md` requires `#[serial(hort_pg_db)]`
  for DB-touching tests; `scanner_registry_repository.rs` instead uses a
  file-local `lock_serial()` async mutex, a legitimate equivalent for
  *intra-binary* parallelism, documented as mirroring `jobs_repository.rs`.
  Neither mechanism defends against a *separate process* on the same server,
  which is what both failures were. Do not rewrite the isolation here.
- **Do not touch the retry counts or timeouts** in `isolated_db_from` /
  `shared_migrated_pool`. Tuning contention is a different question from
  reporting it honestly, and it needs evidence this item does not have.

## Done when

- A pool-acquisition timeout during test setup panics with a message that
  names acquisition, not migrations, and retains the underlying error.
- A genuine migration failure still panics with an accurate migration message.
- No occurrence of the old string remains at a site that can observe a
  timeout.
- `cargo test --workspace` green; `cargo fmt --check` and
  `cargo clippy --workspace --all-targets -- -D warnings` clean.
