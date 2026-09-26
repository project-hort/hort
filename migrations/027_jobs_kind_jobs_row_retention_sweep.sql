-- 027_jobs_kind_jobs_row_retention_sweep.sql
--
-- Redefines the `jobs.kind` CHECK constraint so it admits
-- `'jobs-row-retention-sweep'` — the general terminal-row retention sweep
-- consumed by `JobsRowRetentionSweepHandler`
-- (`crates/hort-app/src/task_handlers/jobs_row_retention_sweep.rs`).
--
-- Two kind-specific sweeps already existed: `prefetch-row-retention-sweep`
-- over `kind LIKE 'prefetch%' OR kind = 'oci-index-child-ingest'`, and
-- `scan-row-retention-sweep` over `kind = 'scan'`. Every other kind in the
-- list below had no horizon at all and accumulated terminal rows forever;
-- the highest-churn of them, `staging-sweep`, adds roughly 288 rows a day
-- at its five-minute cadence. This kind is the horizon for the remainder.
-- Its predicate is the textual complement of the two sibling sweeps so
-- exactly one horizon is ever in force per kind, and it retains — per kind
-- — the newest `completed` row and the newest terminal row, because
-- `last_completed_at_by_kind` (the two boot-time liveness gauges) and
-- `last_result_summary_by_kind` (the prefetch rotation cursor) both read
-- `status = 'completed'` and would otherwise lose their state to the
-- horizon.
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
-- `023_jobs_kind_scan_row_retention_sweep.sql` /
-- `024_jobs_kind_oci_index_child_ingest.sql` repeated.
--
-- ## The effective-list invariant
--
-- The `jobs.kind` allow-list in force is the one defined by the NEWEST
-- migration that defines it — this file, until a later migration redefines
-- the constraint again. Widening the set therefore means: copy the list
-- from the newest defining migration (024), add the new literal, and
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
-- Expand/contract: this migration is purely additive — widening a CHECK
-- IN-list rejects nothing that was previously accepted — so it carries no
-- `migrations/CONTRACTIONS.toml` entry (ADR 0030).
--
-- Reversal (sqlx::migrate! is UP-only; no paired *.down.sql): drop
-- `jobs_kind_check` and re-add it over the list below minus
-- `'jobs-row-retention-sweep'`, after deleting any row already carrying
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
        'scan-row-retention-sweep',
        'oci-index-child-ingest',
        -- General terminal-row retention sweep for every kind the two
        -- kind-specific sweeps do not reach. Enqueued once per tick by the
        -- `hort-server enqueue-jobs-row-retention-sweep` CronJob on the
        -- runtime DSN, then claimed by the worker like any other task
        -- kind; also admin-invokable (present in
        -- `ADMIN_INVOKABLE_TASK_KINDS`), unlike the DB-CHECK-only kinds
        -- `'scan'` / `'verify-event-chain'` / `'oci-index-child-ingest'`.
        -- The sweep's own terminal rows fall inside its own predicate, so
        -- it reclaims its own history like its two siblings do.
        'jobs-row-retention-sweep'
    ));
