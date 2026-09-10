-- 024_jobs_kind_oci_index_child_ingest.sql
--
-- Redefines the `jobs.kind` CHECK constraint so it admits
-- `'oci-index-child-ingest'` — the per-child task kind consumed by
-- `OciIndexChildIngestHandler`
-- (`crates/hort-app/src/task_handlers/oci_index_child_ingest.rs`). One row
-- per child manifest an OCI image index declares; the handler performs, up
-- front, the verified upstream pull a later lazy client GET would have
-- performed, so a multi-arch image's index quarantine window and its
-- children's windows run concurrently instead of back to back. It shortens
-- no window — the anchor still comes from `first_seen_for_checksum`
-- (ADR 0054) — and a nested index recurses by enqueueing this same kind
-- again, one row per grandchild.
--
-- ## Why a new numbered migration, not an edit of the previous list
--
-- ADR 0022's controlling principle is "no in-place edit once you can't
-- wipe". Databases that cannot be wiped now exist, so every migration that
-- has already been applied is frozen — `sqlx::migrate!` validates the
-- checksum of every applied migration, and ANY edit to one (a comment-only
-- one included) makes an already-migrated database fail its migrate step
-- with `VersionMismatch` and refuse to boot. This file follows the shape
-- `018_jobs_kind_oci_edge_backfill.sql` established and
-- `023_jobs_kind_scan_row_retention_sweep.sql` repeated.
--
-- ## The effective-list invariant
--
-- The `jobs.kind` allow-list in force is the one defined by the NEWEST
-- migration that defines it — this file, until a later migration redefines
-- the constraint again. Widening the set therefore means: copy the list
-- from the newest defining migration (023), add the new literal, and
-- append the result as the next numbered migration.
--
-- The constraint is named explicitly here — 009 declares the CHECK inline
-- on the column, so PostgreSQL auto-names it `jobs_kind_check`; re-adding
-- it under that same name keeps one stable identifier across
-- redefinitions.
--
-- Keep this list in lock-step with `hort_domain::events::EVENT_TASK_KINDS`
-- (`crates/hort-domain/src/events/authorization_events.rs`); per-kind
-- rationale lives with that constant. The DB-free structural guard
-- `crates/hort-adapters-postgres/tests/task_kind_check_lockstep_guard.rs`
-- resolves the effective list exactly as defined above (newest defining
-- migration wins) and fails when the two sides drift.
--
-- GRANTs / role wiring: none — the table already exists under the post-004
-- default-privileges convention (ADR 0009); altering a CHECK constraint
-- touches no privileges.
--
-- Idempotence: the migration runs exactly once via the `_sqlx_migrations`
-- ledger, so the DROP carries no `IF EXISTS` — a missing `jobs_kind_check`
-- means the database's constraint set has diverged from this chain, and
-- the migration must fail loudly rather than mask that.
--
-- Reversal (sqlx::migrate! is UP-only; no paired *.down.sql): drop
-- `jobs_kind_check` and re-add it over the list below minus
-- `'oci-index-child-ingest'`, after deleting any row already carrying that
-- kind.

ALTER TABLE public.jobs
    DROP CONSTRAINT jobs_kind_check;

ALTER TABLE public.jobs
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN (
        'scan',
        'cron-rescan-tick',
        'advisory-watch-tick',
        'retention-evaluate',
        'retention-purge',
        'eventstore-archive',
        'staging-sweep',
        'noop',
        'service-account-rotation',
        'eventstore-checkpoint',
        'replay-seen-prune',
        'quarantine-release-sweep',
        'seed-import',
        'prefetch-tick',
        'prefetch',
        'prefetch-dependencies',
        'prefetch-row-retention-sweep',
        'wheel-metadata-backfill',
        'provenance-verify',
        'scanner-registry-prune',
        'verify-event-chain',
        'policy-reevaluation',
        'oci-membership-edge-backfill',
        'scan-row-retention-sweep',
        -- Eager ingest of one OCI image-index child manifest. Handler-
        -- enqueued only (the index ingest path mints the first generation,
        -- the handler mints each nested generation), never operator-
        -- invoked, so it is deliberately absent from
        -- `ADMIN_INVOKABLE_TASK_KINDS` — a DB-CHECK-only kind, the same
        -- asymmetry `'scan'` and `'verify-event-chain'` carry. Dedup is the
        -- `jobs_idempotency_key_uq` partial unique index over the composed
        -- `oci-index-child-ingest:{repository_id}:{child_digest}` key.
        'oci-index-child-ingest'
    ));
