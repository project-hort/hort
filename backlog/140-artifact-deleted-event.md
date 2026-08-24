# 140 — Artifact deletion becomes an event-sourced soft-delete

Issue: #145.

Deletion is today a bare `DELETE FROM artifacts WHERE id = $1` with no domain
event — the one terminal artifact-lifecycle transition that records nothing.
This item makes it an **event-sourced lifecycle transition**: emit
`ArtifactDeleted`, keep the row (soft-delete), keep the CAS blob. The design
below is the **confirmed spec** (maintainer-approved on #145); build to it.

**Governing decisions:** ADR 0002 (event-sourced lifecycle), ADR 0030
(StreamCategory retention closed-set guards), ADR 0007 (terminal-state
semantics; the `Rejected` kept-but-not-live precedent), ADR 0054 (content-age
anchor `first_seen_at = MIN(created_at)`). This completes the correct version of
what #93's removed `is_deleted` flag only stubbed.

## Read first

- `crates/hort-domain/src/events/artifact_events.rs` — the `ArtifactRejected`
  event + `RejectionReason` (the template) and how artifact events are shaped.
- `crates/hort-domain/src/events/mod.rs` — `StreamCategory` (reuse `Artifact`),
  `StreamId::artifact(id)`, the `PersistedEvent` envelope (actor lives here).
- `crates/hort-domain/src/entities/artifact.rs` — the aggregate, `QuarantineStatus`,
  the `reject_from_*` methods (each mutates state + returns the event),
  `is_downloadable`/`is_promotable`.
- `crates/hort-adapters-postgres/src/artifact_repo.rs` — `SELECT_COLS`, `delete`
  (~ll. 226-243, the bare DELETE to replace), `find_by_id`, `find_by_path`,
  `list_active_for_repo`, `package_version_status` (the reads to filter).
- `crates/hort-app/src/use_cases/artifact_use_case.rs` — `delete` (the
  no-actor pass-through to fix), `find_visible_by_path`/`find_visible_by_id`.
- `crates/hort-http-oci/src/manifests_write.rs` — `delete_manifest_dispatch`
  (the `delete_by_digest` path; `ApiActor { user_id: access.principal.user_id }`
  is available here and currently dropped).
- `migrations/003_artifacts_cas.sql` (the `UNIQUE (repository_id, path)`
  constraint + CHECK) and `migrations/020_drop_artifacts_is_deleted.sql` (why
  the naive soft-delete was removed — the constraint hazard this item resolves).

## Confirmed design

### 1. Domain event `ArtifactDeleted` on `StreamCategory::Artifact`

- New event struct in `hort-domain`: `ArtifactDeleted { artifact_id: Uuid,
  repository_id: Uuid, path: String, content_hash: String }`. **Actor + timestamp
  ride the `PersistedEvent` envelope** (mirror `ArtifactRejected` exactly — do
  NOT put actor/timestamp in the struct). Add the `DomainEvent` variant; handle
  it in every exhaustive match the compiler flags.
- Stream: `StreamId::artifact(artifact_id)` — the artifact's own stream, so a
  replay terminates at `ArtifactDeleted`. **No new `StreamCategory` variant**
  (deletion is not a distinct retention class; `Artifact` already covers it and
  is `RETENTION_PERMITTED`/terminal-gated). This means the ADR-0030 closed-set
  guards (`retention_registration_guard`, `requires_admin`, `Display`, `FromStr`,
  `ALL_CATEGORIES`) are **untouched** — do not add a category.

### 2. Aggregate transition

- Add a `delete(...)` (or similarly named) method on `Artifact` that returns the
  `ArtifactDeleted` event, mirroring the `reject_from_*` shape. It records the
  logical deletion; it does not mutate `quarantine_status` (deletion is
  orthogonal — see §3). Whether it needs an entry in the
  `quarantine_transitions` table depends on your chosen representation; since
  deletion is tracked by `deleted_at` (not `QuarantineStatus`), it should NOT go
  through the `QuarantineStatus` transition table. Keep the domain method pure.

### 3. Projection: a dedicated `deleted_at` column — NOT a `QuarantineStatus` variant

- New migration (next number — verify `ls migrations/ | tail`): add
  `deleted_at timestamptz NULL` to `artifacts`. Do **not** add a
  `QuarantineStatus::Deleted` variant (it would conflate deletion with scan
  state, lose the pre-deletion state, and ripple through every exhaustive match
  + the CHECK constraint). `deleted_at IS NULL` = live; non-null = deleted.
- Same migration: **replace the `UNIQUE (repository_id, path)` constraint with a
  partial unique index** `CREATE UNIQUE INDEX ... ON artifacts (repository_id,
  path) WHERE deleted_at IS NULL;` (drop the old constraint). This is the piece
  the old `is_deleted` lacked — a deleted row no longer blocks a fresh ingest at
  the same path; re-ingest creates a new artifact (new id, new row, new stream).
  Follow the in-place migration convention; verify the migration number is free.
- `artifacts` is NOT on the `no_sensitive_drops` sensitive-table list (that guard
  covers the authz model, credential store, event store, repository config, task
  queue), and migration 020 already precedents `ALTER TABLE artifacts`. Confirm
  the `no_sensitive_drops` guard still passes (the constraint swap is on
  `artifacts`, not a listed table).

### 4. Adapter: soft-delete + emit + read filters

- Rewrite `ArtifactRepository::delete` (Postgres impl) to, in **one
  transaction**: `UPDATE artifacts SET deleted_at = now() WHERE id = $1 AND
  deleted_at IS NULL` (rows_affected 0 ⇒ `NotFound`, preserving idempotency —
  re-deleting an already-deleted or absent artifact is a no-op/NotFound) **and**
  append the `ArtifactDeleted` event to the artifact's stream, atomically. Follow
  the existing `commit_transition`-style pattern the `reject_from_*` path uses so
  the state change and the event commit together (no strand). The trait signature
  must carry the actor (see §5).
- Add `deleted_at` to `SELECT_COLS` and the `Artifact` row mapping.
- Add `AND deleted_at IS NULL` to the live reads: `find_by_id`, `find_by_path`
  (the ingest AND OCI-delete lookup), `package_version_status` (index-serve), and
  any other read that must not surface a deleted artifact as live. `list_active_*`
  already filters on `quarantine_status IN (...)` — add the `deleted_at IS NULL`
  guard there too so a deleted-but-released row is excluded.

### 5. Actor threading (app + http)

- `ArtifactUseCase::delete` gains an actor parameter and passes it through to the
  repo so the event is attributed. `delete_manifest_dispatch`
  (`delete_by_digest`) already has `ApiActor { user_id: access.principal.user_id }`
  — thread it in instead of dropping it.

### 6. Blob unchanged (per-repo deletion)

- Do **not** call `StoragePort::delete`. Blob lifetime stays GC-owned
  (`PurgeUseCase`, refcount-gated via `content_references`). The OCI path's
  existing best-effort `content_references` clearing stays as-is (it releases the
  artifact's reference so refcount GC can later reclaim the blob if nothing else
  references it; it does not remove the blob directly). The row's
  `checksum_sha256` column preserves what content it held for audit.

### 7. ADR 0054 interaction — record, do not change the query

- `first_seen_at = MIN(created_at)` over rows sharing a content hash: a
  soft-deleted row **keeps anchoring** it. That is the fail-safe direction (a
  deleted artifact is still genuine age evidence; excluding it could only shorten
  a window). **Leave the ADR 0054 query unchanged.** Add a one-line invariant
  comment at the anchor query (state the invariant, not the issue number)
  noting that deleted rows deliberately continue to anchor in the safe direction.

## Comments

State the invariant, never the provenance — no `#145`/`item 140`/directive
numbers in any code comment. Panic/event/doc text explains the invariant.

## Acceptance

- A deletion through the OCI manifest `DELETE` route (`delete_by_digest`) emits a
  durable, replayable `ArtifactDeleted` event on the artifact's own stream,
  attributed to the authenticated actor; the `artifacts` row is retained with
  `deleted_at` set.
- Live reads exclude deleted artifacts (`deleted_at IS NULL`); a stream replay no
  longer reconstructs a deleted artifact as live.
- A fresh ingest at the path of a deleted artifact **succeeds** (partial unique
  index), creating a new artifact row + stream. Add a test for this exact
  re-ingest-after-delete case (it is the hazard #93/020 called out).
- Re-deleting an already-deleted or absent artifact is idempotent (no-op/NotFound,
  no duplicate event).
- No `StoragePort::delete` call added; blob GC mechanics unchanged.
- No new `StreamCategory`; `retention_registration_guard` and `no_sensitive_drops`
  pass. Domain unit tests for the new event/transition; adapter tests carry
  `#[serial(hort_pg_db)]`.

## Starter prompt

/hort-architect

Implement issue #145 per `backlog/140-artifact-deleted-event.md` (the confirmed
spec) on branch `agent/145-artifact-deleted-event`. Read the "Read first" files,
then build §1–§7. Key invariants: reuse `StreamCategory::Artifact` (no new
category); soft-delete via a new `deleted_at` column (no `QuarantineStatus::Deleted`
variant); swap `UNIQUE (repository_id, path)` for a partial unique index `WHERE
deleted_at IS NULL`; emit `ArtifactDeleted` atomically with the state change;
thread the OCI actor through `ArtifactUseCase::delete`; do not touch blob GC; leave
the ADR 0054 anchor query unchanged. Full gate green (fmt/clippy/`cargo test
--workspace`/audit/deny). Confirm acceptance, especially the re-ingest-after-delete
test.
