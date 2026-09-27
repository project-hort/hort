# 249 — Test doubles and test output that flatter production

**Issue:** #303 · **Branch:** `agent/303-db-test-serialization`
**Governing decisions:** CLAUDE.md *DB-backed test isolation
(parallel-safety contract)* · `ed79360a` (the flake the serial key fixed) ·
#37 (the isolation harness) · ADR 0039 D5 (the read-path hold, context for D).

## Why

One family of defects: doubles, tolerances and output that make production look
more generous or quieter than it is. The `MockArtifactRepository::insert` find
kept a whole error class invisible; these are the same shape. One pass through
one corner.

All figures below were measured on `99d52c2e`.

## A — the serialization key

### A.1 Its reach is not what the docs claim (measured)

CLAUDE.md justifies `#[serial(hort_pg_db)]` by cluster-global work — `CREATE
ROLE`, `CREATE`/`DROP DATABASE`, `pg_stat_activity`, the shared catalogs — and
says the key "is what keeps that collision from happening". Two measurements:

1. `serial_test = "4"` with default features and **no `fslock` in
   `Cargo.lock`**, so `#[serial(key)]` is a **process-local** lock.
2. cargo 1.98.1 runs test binaries **strictly sequentially**: three 3-second
   targets, `a` ends at `…511895`, `b` starts at `…511896`.

So the whole threat is **intra-binary** (libtest runs a binary's tests on many
threads). The key covers exactly that — and so does a file-local mutex. Between
binaries there is nothing concurrent to serialize.

The tree contradicts itself: `hort-adapters-postgres/tests/rescan_candidates.rs`
calls the key "the cross-binary lock" (false);
`hort-worker/tests/composition_smoke.rs` states it correctly.

**The load-bearing consequence:** the protection is a property of the *runner's*
sequential scheduling, not of the key. `cargo nextest` runs test binaries in
parallel by default; adopting it would void the assumption silently while
CLAUDE.md still promises cover. That dependency belongs in the rule, and it is
the strongest argument for the guard.

### A.2 The gap

Files that take a real connection and carry no key:

| file | tests | key | file-local mutex |
|---|---|---|---|
| `hort-adapters-postgres/tests/jobs_repository.rs` | 18 | 0 | 18 |
| `hort-adapters-postgres/tests/scanner_registry_repository.rs` | 6 | 0 | 6 |
| `hort-adapters-postgres/tests/user_deactivation_notify.rs` | 4 | 0 | 4 |
| `hort-adapters-postgres/tests/api_tokens_migration.rs` | 4 | 0 | 3 |
| `hort-adapters-postgres/tests/sbom_components.rs` | 4 | 0 | 0 |
| `hort-adapters-postgres/tests/ingest_enqueue_atomicity.rs` | 2 | 0 | 0 |
| `hort-server/tests/gitops_retention_scope_real_db.rs` | 4 | 0 | 0 |
| `hort-server/tests/task_use_case_enqueue_real_db.rs` | 1 | 0 | 0 |
| `hort-server/tests/migrate_assert_current.rs` | 10 | 0 | 0 |
| `hort-server/tests/migrate_schema_compat.rs` | 10 | 0 | 0 |
| `hort-server/tests/migrate_harden_events.rs` | 3 | 0 | 0 |
| `hort-worker/tests/schema_compat_boot.rs` | 7 | 0 | 0 |

Partly keyed: `rescan_candidates.rs` — 20 tests, 10 keyed, **all 20** taking
`lock_serial()`.

The last four rows are the **third isolation mode** (hand-rolled fixtures that
drive the migrator itself and so cannot be handed a migrated database). They
escape the rule only on its wording — it names `hort-adapters-postgres`, and
they live in `hort-server`/`hort-worker` — while sitting squarely inside its
rationale: they run `CREATE DATABASE` plus the full migration set, cluster-global
`CREATE ROLE` included. Only `migrate_fleet_fence.rs` (6 tests) carries the key.

**These counts are inventory, not acceptance.** Earlier drafts of this work said
"six files / 24 tests" and "29 tests"; both undercounted, and one listed a file
as keyed that is not. What counts is what the guard in A.4 finds.

### A.3 Two files justify the omission wrongly

- `api_tokens_migration.rs` puts a file-local `Mutex` where the key belongs.
  Per A.1 that is equal in reach, not worse — but it is a **second** mechanism,
  and two independent serializations do not compose into one order: a test
  holding only one and a test holding only the other run concurrently. No file
  is in that state today (in `rescan_candidates.rs` the keyed tests take the
  mutex too), but it is one edit away and a reviewer cannot rule it out by
  inspection. That — not reach — is why one mechanism wins.
- `gitops_retention_scope_real_db.rs` and `ingest_enqueue_atomicity.rs` write in
  their module docs that no key is required because they isolate per test. That
  is the reasoning CLAUDE.md explicitly rejects. A refuted reason is worse than
  none: the next reader takes it for checked.

### A.4 Decided — the structural guard ships

The rule has no compile-time and no lint enforcement, and it has decayed across
three crates and roughly eighty test functions; review discipline did not hold
it. This repository has an established form for the class: DB-free source scans
under `crates/*/tests/` (`no_bcrypt`, `retention_registration_guard`,
`expand_contract_guard`, `db_gate_not_silent`) — sub-second, carried by
`cargo test --workspace` automatically. Without one this work recurs.

Counter-argument weighed and rejected: a source scan is regex-shaped and a
helper can hide the connect from it. `db_gate_not_silent` already accepts that
limit for the same family; the guard's job is to make the **common** shape
impossible to land silently, not to be a type system.

**No allow-list.** Every site the guard reports gets the key. A site that must
justifiably not carry it is a report finding, not an entry to silence it with.

### A.5 Decided — the rule's wording widens

From "every new `hort-adapters-postgres` test that acquires a real connection"
to **every test in the workspace that acquires a real Postgres connection**,
whatever the crate. The rationale is crate-agnostic; the third mode fell through
the wording alone.

## B — three doc comments name webhook headers that are not sent

| site | says | actually sent |
|---|---|---|
| `Cargo.toml:326` | `X-Ak-Signature` | `X-Hort-Signature` (`hort-notifier-webhook/src/lib.rs:416`) |
| `crates/hort-domain/src/entities/subscription.rs:138` | `X-Ak-Signature` | same |
| `crates/hort-domain/src/ports/event_notifier.rs:121` | `X-Ak-Subscription-Id` | `X-Hort-Subscription-Id` (`:417`) |

The Diátaxis page is right; only these three comments are wrong — and two of
them sit on the domain entity and the port trait, exactly where someone
building a receiver looks.

## C — a green run prints a `FAIL:` line

`scripts/native-tests/run.sh:429` prints
`printf '  FAIL: %s\n' "${FAILED[@]:-}"`. On an empty array `"${arr[@]:-}"`
expands to *one empty word*, so the line always comes. On the #240 E2E run it
landed against the compose teardown output and read as a failure
(`[+] down 13/13`) with `FAIL=0` printed directly above it. Same shape applies
to all four lists.

## D — `build_mock_ctx` wires no policy projections into `ArtifactUseCase`

Every format-handler test asserting a `Retry-After` silently checks
`DefaultPolicy` instead of the configured policy — the `None` arm of
`ArtifactUseCase::resolve_quarantine_window`. The #240 run tripped over exactly
this (`57599` instead of `144000`) before it reached the
`with_provenance_hold_hydration` opt-in.

Today's state is deliberate: the harness seeds `quarantineDuration: 0`, so
wiring the port by default would rewrite every existing assertion. **Cheapest
sufficient close:** make the unwired arm warn instead of silently defaulting.
The server composition root wires the port
(`crates/hort-server/src/composition.rs:2849`), so the warning is free there —
verify that for *every* production construction site before making the change,
and report instead of warning if one legitimately leaves it unwired. The
inversion the opt-in's comment contemplates is not part of this work.

## E — a silent skip survives, and the new guard cannot see it

`hort-worker/tests/composition_smoke.rs::build_app_context_registers_seed_import_handler`
swallows **every** error out of `build_app_context` and returns
(`Err(e) => { eprintln!(…); return; }`). The stated intent is tolerating a
missing `trivy`/`osv-scanner` on `PATH` — but a dead database takes the same
branch. Measured after the DB-gate work: the test still reports `ok` against an
unreachable `DATABASE_URL`.

It is not a connect-and-discard, so `db_gate_not_silent` does not catch it.
Closing it means classifying the error out of `build_app_context` — a change to
error typing in production code, not to the harness.

## Acceptance

- A new DB-free guard under `crates/*/tests/` scans the sources (inline
  `#[cfg(test)]` **and** `tests/` targets) and reports every test function that
  acquires a real Postgres connection without carrying `#[serial(hort_pg_db)]`.
  The guard is green. No allow-list.
- No file-local serialization mutex remains beside the key: the `lock_serial()`
  gates are gone and their files carry the key.
- `grep -rn "no .#\[serial(hort_pg_db)\]. key is required"` is empty, and the
  "cross-binary lock" sentence in `rescan_candidates.rs` is gone.
- CLAUDE.md states the key's **measured** reach (process-local, `file_locks`
  off) and its dependence on the runner's sequential test-binary scheduling,
  including the consequence that a parallel runner breaks the assumption. The
  obligation's wording is widened per A.5.
- `grep -rn "X-Ak-" crates/ Cargo.toml` is empty. The scope is code and
  doc comments — this item's own table names the wrong header in order to
  record the defect, the same carve-out `CHANGELOG.md` and ADR prose get
  from the comment rule.
- A run with no failures prints no `FAIL:` line; same shape for all four lists.
- The unwired policy-projection arm warns instead of silently defaulting, after
  confirming no production site takes it.
- `composition_smoke` distinguishes a missing scanner binary from every other
  error out of `build_app_context`; a dead database fails the test rather than
  reporting `ok`.
- Gate green.
