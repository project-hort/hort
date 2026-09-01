# 148 — Cargo sparse index serves `pubtime` per line

Issue: #217 (analysis record on #207).

When a sparse-index line carries no `pubtime`, Renovate's crate datasource
falls back to `GET {api}/v1/crates/{name}/{version}` — a route hort never
implemented — producing 10–13 uncached 404s per nightly run and losing the
`releaseTimestamp` that age-based consumer rules (`minimumReleaseAge`) use.
Consumer contract (verified at the Renovate source 2026-08-30): the crate
datasource reads `vers`, `yanked`, `rust_version`, `pubtime` per line;
`pubtime` goes through `asTimestamp()` (ISO 8601 accepted); when it yields
a timestamp, the fallback request is skipped entirely. Cargo clients
ignore unknown index-line fields; serving publish times in the index is
cargo upstream's own direction (rust-lang/cargo#15491).

**Governing decisions:** ADR 0016 (one-way outward: the served timestamp
is derived from stored fields the gates already own and is NEVER read back
into gate/policy computation; no interaction with
`trust_upstream_publish_time`) · ADR 0031 (virtual: pass-through of the
winning member entry) · ADR 0026 (projection contract) · cargo index
forward-compat + cargo#15491.

## Read first

- `docs/architecture/explanation/index-construction.md` — the unified
  Source → Filter → Builder pipeline.
- `crates/hort-http-cargo/src/index_source.rs` — both sources
  (`HostedCargoSource`, `ProxyCargoSource`); where entries are built and
  status is hydrated.
- `crates/hort-formats/src/cargo/index.rs` — `CargoIndexBuilder`, the
  line-emission site and its test style.
- `crates/hort-http-cargo/src/index_cache.rs` — the Redis-cached
  projection (`CargoVersionLine`) the proxy source consumes.
- `crates/hort-http-cargo/src/upstream_pull.rs` (~l. 389) — where
  `upstream_published_at` is captured (tarball `Last-Modified`).
- `crates/hort-app/src/use_cases/index_serve.rs` — `PerVersionPayload::Cargo`.

## Confirmed design

Optional `pubtime` field per served index line, **RFC 3339 UTC**, one-way
outward through the existing pipeline:

1. `CargoVersionPayload` gains `pubtime: Option<DateTime<Utc>>`;
   `CargoIndexBuilder` emits it as RFC 3339 when present, omits the key
   when `None`.
2. Timestamp source per repo kind:
   - **hosted**: the artifact's `created_at` (publish time at this
     registry — authoritative).
   - **proxy**: `upstream_published_at` when present, else `created_at`
     (first-seen here — conservative for age-gating consumers), else
     **omit** (version known upstream but never ingested: hort has no
     knowledge and must not invent one; the consumer fallback remains for
     exactly these versions, honestly).
   - **virtual**: the winning member entry's value passes through — no
     aggregation-level synthesis.
3. The cached proxy projection (`CargoVersionLine`) gains the field.
   Previously-cached projections lacking it serve without `pubtime` until
   natural refresh — no forced invalidation (the degradation is the status
   quo and self-heals). State this in the projection's doc.
4. NOT in scope: the REST route
   `GET /{repo}/api/v1/crates/{name}/{version}` (serving the field removes
   the requests instead of answering them; the route would 404 for
   never-ingested versions anyway).

## Acceptance

- Builder: RFC 3339 emission when present, key omitted when `None` (pinned
  in the existing builder test style).
- Hosted source: `pubtime` = `created_at`.
- Proxy source: precedence `upstream_published_at` → `created_at` →
  omitted (never-ingested), each covered; cached-projection round-trip
  (old projection without field still parses and serves) covered.
- Virtual: winning member's value passes through.
- No gate/policy code path reads the new field — the field appears only in
  payload/projection/builder types (review check; state it in the report).
- Comment discipline: invariants, no issue refs.
