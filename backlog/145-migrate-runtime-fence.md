# 145 — Runtime fence: `migrate` refuses to run against a live older fleet

Issue: #214, second item (dispatched after item 144 lands on the branch).

Item 144's guard prevents *shipping* a same-release contraction. This item
converts the remaining operator-ordering mistake — applying a legitimately
deferred contraction while old binaries are still connected — from an outage
into a refused command.

**Governing decisions:** ADR 0030 (amended by item 144; this is the runtime
layer the amendment names), ADR 0048 (deploy model).

## Confirmed design

1. **Version-stamped connections.** Every hort Postgres connection sets
   `application_name = "hort-{server|worker}/<workspace version>"` (the pool
   options in the composition root; one place, both binaries).
2. **Fence in `hort-server migrate`.** Before applying pending migrations,
   query `pg_stat_activity` for hort-prefixed `application_name` rows other
   than self. If any connected client's version is **older than the current
   binary's**, and at least one pending migration is listed in
   `migrations/CONTRACTIONS.toml` (item 144's manifest — the fence gates
   only contractions, not expand migrations), refuse with a clear error
   naming the offending clients and versions.
3. **Override:** `--allow-running-fleet` flag (and matching env var for the
   Helm hook) applies anyway — the emergency path, logged loudly.
4. **Graceful degradation:** clients predating this item carry no version in
   `application_name`; treat "hort-shaped but unversioned" as *older*
   (fail-closed), and any non-hort `application_name` as unrelated.
5. Expand-only migration sets are never fenced — routine rolling upgrades
   stay hook-driven and unattended.

## Read first

- `crates/hort-server/src/migrate.rs` — the runner to extend.
- The composition root's pool construction (follow `PgPoolOptions` /
  connect options in `crates/hort-server/src/`) — where
  `application_name` is set.
- `backlog/144-migration-expand-contract-guard.md` — the manifest format the
  fence reads.
- The Helm pre-upgrade hook template
  (`deploy/helm/hort-server/templates/`) — where the env override must be
  plumbable (default OFF).

## Acceptance

- DB-gated integration test (`#[serial(hort_pg_db)]` — mandatory key):
  a second connection with an older-version `application_name` + a pending
  manifest-listed migration ⇒ migrate refuses; with `--allow-running-fleet`
  ⇒ applies; expand-only pending set ⇒ applies without the flag; unversioned
  hort-shaped client ⇒ refuses.
- Both binaries stamp `application_name` (assert via `pg_stat_activity` in
  the same test).
- Helm hook: override plumbed, default off; chart docs note it.
- Comment discipline: invariants, no issue refs.
