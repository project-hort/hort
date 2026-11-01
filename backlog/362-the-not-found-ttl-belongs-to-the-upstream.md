# 362 — The not-found TTL belongs to the upstream, not to the deployment

**Issue:** #391 (follow-on) · **Branch:** `agent/391-not-found-ttl-per-repository` · single item.

## Why

`PullDedup` keeps four negative-cache TTLs by failure class, all **global**:
`ttl_not_found` 30 s, `ttl_unavailable` 10 s, `ttl_timeout` 10 s,
`ttl_checksum_mismatch` 60 s (`crates/hort-app/src/pull_dedup.rs:132-190`),
each wired from an env var.

One value cannot be right for two upstreams with opposite behaviour, and
`maven-virtual` has both:

- `maven-central` never gains a coordinate it refused — a release is immutable
  and absent is absent. A long TTL is free.
- `maven-spring-snapshots` gains coordinates constantly. A long TTL would
  answer `404` for a snapshot that has since been published, which is the
  failure mode that makes a developer distrust the registry.

30 s is tuned for a 404-storm dedup window, not for "Central does not have
this, and will not tomorrow either". The maintainer's decision (2026-11-01):
make it per-upstream, keeping the global value as the default.

**This does not replace `backlog/361`.** A negative cache helps *repeats*;
within one Maven build each coordinate is resolved once, so a cold build
resolving 300 coordinates with 100 missing still pays the full per-coordinate
cost. Existence-first cuts that; the TTL cuts the next build. Complementary.

## The operator surface

A field on **`RepositoryUpstreamMapping`** — the gitops document that already
owns the relationship to one upstream. Not on the repository: a virtual
repository has no upstream at all, and the TTL is a statement about an
upstream's behaviour.

`notFoundCacheSeconds`, optional. Absent → the deployment-level default.

**Zero.** The global knob rejects `0` with `ConfigError::ValueNotPositive`,
because "a zero TTL would re-fetch on every retry within the negative-cache
window, defeating the coalescing benefit on 404 storms"
(`crates/hort-server/src/config.rs:548-556`). Mirror that: reject `0` at
**apply** time with a named linter rejection rather than accepting it and
behaving unexpectedly. State in the report which rule id you used.

## Threading it

`ttl_for(kind, &self.config)` reads the TTL off the `PullDedup` instance's own
config (`pull_dedup.rs:214`, called at `:1202` and `:1330`), and
`coalesce_blob(key, fetch_fn)` takes no TTL (`:801`).

**Pass the override per call.** The Maven pull already resolves the mapping
before it fetches anything, so the caller knows the value; give the coalesce
entry points it uses an `Option<Duration>` not-found override, `None` meaning
the global default, and thread it into `ttl_for`.

**`:1330` matters as much as `:1202`, but not for the reason an earlier draft
of this item gave.** It does **not** produce a `Retry-After` — corrected
2026-11-01 after an independent review caught the claim. `:1329-1330` sets
`DedupOutcome::Failed { expires_at_unix_secs }` for the **local in-process
broadcast** to followers on Layer B, and `handle_follower_outcome` (`:1495`)
reconstructs a plain `AppError` from the leader's message with no header
involved. Do **not** write a test asserting a `Retry-After`; there is none on
this path.

The real requirement is that the two sites are two **independent** expiry
calculations for the same miss: `:1202` is the cluster negative-cache entry and
`:1330` is the local follower expiry. An override reaching one and not the other
makes an in-process follower and a second replica disagree about how long the
same coordinate stays absent — the same artifact answering 404 for 30 s on one
pod and an hour on another. Both sites or neither.

The serialized expiry and the cluster-store TTL (`:1217`) are downstream uses of
`:1202`'s calculation, not independent reads of `ttl_not_found` — so threading
the override into `ttl_for` at those two call sites is sufficient. Confirmed by
grep: `ttl_not_found` appears only in the config field, its default, the
`ttl_for` match arms, tests, and config wiring.

Considered and rejected: putting the override on `DedupKey` (the key is
identity, not policy — two callers with different TTLs would get different
cache entries for the same artifact), and giving `PullDedup` a port to look
mappings up itself (a new dependency plus an invalidation problem on gitops
apply, for a value the caller already holds).

## Scope

- Only `ttl_not_found`. The other three stay global; the argument for
  per-upstream variation is about *absence*, and no one has measured a need for
  per-upstream timeout or rate-limit windows. If you think one of them has the
  same shape, report it rather than widening.
- Only the coalesce entry points the Maven pull uses. Others pass `None`.

## Acceptance

- A mapping with `notFoundCacheSeconds: 3600` negative-caches a miss for an
  hour; one without it uses the deployment default; measured, not asserted from
  the config value.
- The **local follower expiry** (`:1330`) reflects the **override**, not the
  global default — same as the cluster negative-cache entry (`:1202`). A test
  pins this specifically; a correct cluster TTL beside a stale local one is the
  regression this unit could introduce. (There is no `Retry-After` on this path
  — do not assert one.)
- `notFoundCacheSeconds: 0` is **rejected at apply**, with the rule id in the
  report.
- The field is enforced by the consumer, so no accepted-but-inert situation
  arises — CLAUDE.md's hard block. Demonstrate the enforcement; do not assert
  it.
- Existing `PullDedup` tests pass **unmodified**, including the `ttl_for`
  table tests at `:2052-2061`.
- `docs/architecture/reference/*` gains the field where the other
  `RepositoryUpstreamMapping` fields are documented.
- `CHANGELOG.md`: one `### Added` line — an operator gains a knob and needs to
  know what it is for.
