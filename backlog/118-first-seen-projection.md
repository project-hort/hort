# 118 — `first_seen_at`: the content-level age projection (write path)

Issue: #163. **Authority: [ADR 0054](../docs/adr/0054-content-level-age-evidence-anchors-quarantine.md)**
— read it first; it is the decision this implements. The ADR text is
committed on this same branch (`9851c088`) and rides with the
implementation MR, so the decision and its realisation land together.

First of two units. This one records the fact; backlog 119 consumes it.
Splitting keeps each MR reviewable — but 118 alone changes **no**
observable behaviour, which is deliberate: it is a foundation, not an
operator-visible half-feature.

## What

Per **content hash**, hort must hold `first_seen_at` = the minimum over
its own ingest observations across every repository of the instance.

1. **Storage** — a content-level record keyed by the SHA-256 content hash.
   New migration (check `ls migrations/ | tail -5` for the next free
   number; 017 is taken). It must NOT be a column on `artifacts`: that
   table is per-repository, and ADR 0054 requires the fact to survive
   deletion of individual per-repo rows.
2. **Survival** — verify against the retention/GC paths that nothing
   cascades this record away when the last per-repo row for that hash is
   purged. If a cascade exists, breaking it IS part of this item; state
   in the report which paths you checked (`retention_purge`,
   `retention_evaluate`, blob GC) and what you found. Cross-check the
   `no_sensitive_drops` structural guard's maintained table list — decide
   and justify whether this table belongs on it (a `DROP` of the age
   record silently weakens every future quarantine anchor).
3. **Write path** — every ingest observation updates the record with a
   monotone minimum: insert on first sight, and on a later observation
   keep the earlier value. `min` must be enforced at the storage layer
   (`ON CONFLICT … DO UPDATE … LEAST(...)` or equivalent), NOT by a
   read-modify-write in application code — concurrent ingests of the same
   hash across repositories are the normal case, and a read-modify-write
   loses the race it is meant to survive.
4. **Both minting paths** record the observation: `ingest_inner` and
   `register_by_hash_inner`. A coalesced follower observes the content
   exactly as a leader does — that symmetry is the point of the ADR.
5. **Port + adapter** — a new outbound port in `hort-domain` with its
   Postgres adapter; `hort-app` depends on the port only. Adapter tests
   are DB-gated and MUST carry `#[serial(hort_pg_db)]`.

## Out of scope (backlog 119)

Anchor derivation, the trusted-upstream second source, and any change to
quarantine timing. After this item the projection exists and is written;
nothing reads it yet.

## Constraints

- Comment provenance rule: invariants only, no tracker references.
- `hort-domain` / `hort-app` are 100 %-coverage crates.
- No change to `artifacts`, to the ingest gate ordering, or to the
  quarantine transition in this item.

## Acceptance

- Two ingests of the same content in different repositories leave ONE
  record whose value is the earlier observation, regardless of order.
- A concurrent-ingest test (or an explicit argument from the SQL's
  atomicity, stated in the report) shows the minimum survives the race.
- Purging the last per-repo row for a hash leaves the record intact.
- `cargo test --workspace` green; fmt/clippy/audit/deny clean.
