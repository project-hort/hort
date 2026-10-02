# 245 — A cluster in recovery turns DB-gated tests into silent passes

**Issue:** #302 · **Branch:** `agent/302-db-gate-silent-skip`
**Governing decisions:** #37 (the isolation harness) · CLAUDE.md *DB-backed test
isolation* · #236 / #298 (the runs during which the cluster went into recovery
and this surfaced).

## Why

During the #298 gate the sandbox Postgres went into recovery for seven minutes.
DB-backed tests reported `... ok` **without having run**.

The chain is two links, and only the second is wrong:

1. Each DB-backed module has its own `maybe_pool()`:
   `let url = env::var("DATABASE_URL").ok()?;` then
   `isolated_db_from(&url).await?`. **The first link is correct** — no
   `DATABASE_URL`, no database, skip. That is the documented contract and it
   must stay.
2. `isolated_db_from` then returns `None` on **any** failure: URL parse,
   maintenance connection, `CREATE DATABASE`, pool connect. The caller cannot
   distinguish that from "not configured", returns early, and the test reports
   `ok`.

**The function's own justification does not apply to it.** Its doc comment says
it returns `None` *"so the suite stays green when `DATABASE_URL` is unset / the
DB is unreachable"*. The unset half is handled one level up — every caller
checks `env::var` first, so `isolated_db_from` never sees that case. What is
left is only the unreachable half, and that is precisely the case that must not
be green.

## Why it matters beyond tidiness

The result is not *uncertain*, it is **positively false**: `passed`, not
`ignored`. So the state in which "gate green" is most needed — the server has a
problem — is the state in which the claim inverts. And the `ignored` count is
not even a lower bound on what was skipped, because the early-return path
reports `ok`.

This repository has shipped a lot of work today on the strength of
`cargo test --workspace` being green.

## Scope

Fix it where the information exists: **a caller that supplied a URL and got
`None` back must be able to tell why**. The natural closure is that
`isolated_db_from` stops flattening "the configured database did not work" into
the same value as "there is no database". Whether that is a hard failure inside
the helper, a distinguishable return, or something else is the unit's call —
but it must not require editing 36 near-identical `maybe_pool` copies to be
correct, and a test that does nothing must not report `ok`.

Do not touch the `env::var` skip. A workspace run with no `DATABASE_URL` must
stay green, because that is how the pre-push gate runs.

## To establish first

- **How many of the 59 callers take the early-return path, and how do they
  report?** `ok` versus `ignored`, per caller shape. That decides how large the
  silent set is and whether a single change reaches all of it.
- **The same question for `shared_migrated_pool`** (4 callers), which has its
  own connect path.
- **What CI does today.** `test:integration` sets `DATABASE_URL`; if the server
  is unreachable there, does the job fail or pass? That is the behaviour this
  item is defending, so measure it rather than assuming.

## Acceptance

- A set-but-unreachable `DATABASE_URL` does **not** produce a green run.
- An unset `DATABASE_URL` behaves exactly as today: the suite runs DB-free and
  stays green.
- The census from *To establish first* is in the report.
- CLAUDE.md's statement that DB-gated tests report `ignored, requires
  DATABASE_URL` either becomes true or is corrected — today the early-return
  path reports `ok`.
- The fix does not require a change in each of the 36 `maybe_pool` copies.
- Gate green.

## Explicitly not in this item

- No consolidation of the 36 `maybe_pool` copies into one helper. Worth doing,
  not here — say so if the census makes it look cheap.
- No change to the per-test isolation model, the migration retry, or the
  stale-database sweep.
