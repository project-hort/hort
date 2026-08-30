-- 023_jobs_kind_scan_row_retention_sweep.sql
--
-- Redefines the `jobs.kind` CHECK constraint so it admits
-- `'scan-row-retention-sweep'` — the periodic task kind consumed by
-- `ScanRowRetentionSweepHandler`
-- (`crates/hort-app/src/task_handlers/scan_row_retention_sweep.rs`). The
-- task deletes terminal (`status IN ('completed', 'failed')`)
-- `kind = 'scan'` rows older than a configurable horizon (default 7
-- days) — the only jobs-table sweep before this one was scoped to
-- `kind LIKE 'prefetch%'`, so every successful scan and every
-- permanently-failed scan left a terminal row forever.
--
-- ## Why a new numbered migration, not an edit of 009's inline list
--
-- ADR 0022's controlling principle is "no in-place edit once you can't
-- wipe". Databases that cannot be wiped now exist (they hold real
-- published artifacts), so `009_scan_jobs_and_findings.sql` is frozen —
-- `018_jobs_kind_oci_edge_backfill.sql` already established this
-- precedent for the same reason: `sqlx::migrate!` validates the
-- checksum of every applied migration, and ANY edit to 009 — a
-- comment-only one included — makes an already-migrated database fail
-- its migrate step with `VersionMismatch` and refuse to boot. This file
-- follows the same shape 018 established.
--
-- ## The effective-list invariant
--
-- The `jobs.kind` allow-list in force is the one defined by the NEWEST
-- migration that defines it — this file, until a later migration
-- redefines the constraint again. Widening the set therefore means:
-- copy the list from the newest defining migration (018), add the new
-- literal, and append the result as the next numbered migration.
--
-- The constraint is named explicitly here — 009 declares the CHECK
-- inline on the column, so PostgreSQL auto-names it `jobs_kind_check`;
-- re-adding it under that same name keeps one stable identifier across
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
-- `'scan-row-retention-sweep'`, after deleting any row already carrying
-- that kind.

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
        -- Terminal `kind='scan'` row retention sweep: mirrors
        -- `prefetch-row-retention-sweep` scoped to `kind = 'scan'`
        -- exactly, never any other kind's terminal row.
        'scan-row-retention-sweep'
    ));
