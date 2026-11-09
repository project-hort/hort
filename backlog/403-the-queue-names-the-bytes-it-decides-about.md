# 403 — The queue names the bytes it decides about

**Issue:** #176 · **Branch:** `agent/176-a-decision-binds-to-the-bytes` ·
item 1 of 3. Part A of the issue spec.

**Governing decisions:** ADR 0030 (soft delete — the queue's own predicate
already carries `deleted_at IS NULL`, and a new join must not reintroduce a
deleted row), ADR 0008 (the projection stays in the adapter; the domain entry
carries a value, not a query). Nothing governs what a queue row must show;
the issue spec decides that.

## The property

**A curator decides over bytes, so the row they decide from names the
bytes.** Half of this landed with #400: the row carries `path`, and for OCI
the path *is* the digest (`manifests/sha256:<hex>`, `blobs/sha256:<hex>`),
because `version` is `NULL` by construction there
(`crates/hort-http-oci/src/coords.rs:61`, `:81`). The other half is open in
two ways that matter:

- for every **non-OCI** format the path carries no content digest, so a
  curator reviewing a crate or a wheel still cannot see which bytes the row
  is about;
- a digest parsed back out of a path is not an addressing key. Item 2
  resolves `waive-digests` against `artifacts.checksum_sha256`
  (`migrations/003_artifacts_cas.sql:55`, indexed at `:116`), and the queue
  has to show the column the decision is addressed by.

## Where it stands today

- Domain entry: `CurationQueueEntry`
  (`crates/hort-domain/src/ports/curation_queue_repository.rs:30`) — no
  `checksum_sha256`, no `tags`.
- Adapter: the projection
  (`crates/hort-adapters-postgres/src/curation_queue_repository.rs:201-207`)
  drives off `artifacts a` already, so the digest is one projected column
  and no new join; the `FromRow` shape is at `:344`.
- HTTP DTO: `CurationQueueEntryDto`
  (`crates/hort-http-core/src/handlers/admin/curation/queue.rs:126`).
- CLI DTO + table: `crates/hort-cli/src/curation/queue.rs:97`.

## What to build

1. **`checksum_sha256: String`** — bare 64-hex, matching `ContentHash` —
   through the domain entry, the adapter row and its `SELECT`, the HTTP DTO
   and the CLI DTO. The CLI table renders the first 12 hex; the JSON output
   carries the full digest. `artifacts.checksum_sha256` is
   `character(64) NOT NULL`, so this is not an `Option` anywhere.
2. **`tags: Vec<String>`, display-only** — a `LEFT JOIN LATERAL` over
   `mutable_refs` aggregating `ref_name` where
   `(repository_id, target_hash) = (a.repository_id, a.checksum_sha256)`.
   The partial index `idx_mutable_refs_target_hash` on
   `(repository_id, target_hash) WHERE target_hash IS NOT NULL`
   (`migrations/003_artifacts_cas.sql:319`) is exactly that shape, and the
   queue caps at `limit ≤ 500`, so the join stays cheap. Empty vector when
   nothing points at the bytes.
3. **Tags are never an addressing key** — not here, not in item 2, not in
   the CLI. A tag is a mutable pointer and a curation decision binds to the
   bytes that were reviewed. The CLI renders tags as an annotation column
   only.

## Acceptance

- The queue shows the digest for an OCI entry and for a `version`-bearing
  entry, in the HTTP JSON, the CLI JSON and the CLI table (truncated there).
- Tags render when `mutable_refs` points at the artifact's bytes and are
  absent from every addressing path in the change.
- The lateral join does not widen the row set: a row with no tags still
  appears exactly once.
- A soft-deleted artifact is still excluded — the new join must not become a
  second, unfiltered read of `artifacts`
  (`live_reads_exclude_deleted` is the guard that will say so).
- The change adds no uncovered lines in `hort-domain` / `hort-app`;
  adapter and HTTP crates stay at or above their tier.
