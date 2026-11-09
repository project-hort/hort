-- 041_jobs_kind_api_token_retention_sweep.sql
--
-- Redefines the `jobs.kind` CHECK constraint so it admits
-- `'api-token-retention-sweep'` — the horizon on the credential store,
-- consumed by `ApiTokenRetentionSweepHandler`
-- (`crates/hort-app/src/task_handlers/api_token_retention_sweep.rs`).
--
-- ## What this kind is, and how it differs from its three siblings
--
-- Every other row-retention sweep in the family reclaims rows from
-- `public.jobs` — the task queue. This one reclaims rows from
-- `public.api_tokens`, the table that decides who may do what. The table
-- grows on its own and had no horizon at all: a row is written per issued
-- credential, the federation branch of `/auth/token-exchange` writes one
-- per workload exchange, and nothing in the tree deleted one.
--
-- The predicate selects a row by **its own non-NULL mark**: a row whose
-- `expires_at` is more than the horizon in the past, or whose `revoked_at`
-- is. Both columns are nullable and a row with neither set is a durable
-- identity that never expires, so it matches neither disjunct and
-- survives — which is the whole safety property, because the alternative
-- is a sweep that deletes live credentials. The horizon is 90 days
-- (`DEFAULT_HORIZON` in the handler), capped at 365.
--
-- The 90-day window is also the decision that `last_used_at`,
-- `last_used_ip` and `last_used_user_agent` are not worth keeping past
-- it: those three live nowhere else in the system — the event store keeps
-- `ApiTokenIssued`, `ApiTokenRevoked` and `ApiTokenUsed`, not those
-- fields — so the sweep is the only thing that ever discards them, and
-- that is deliberate rather than incidental.
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
-- `024_jobs_kind_oci_index_child_ingest.sql` /
-- `027_jobs_kind_jobs_row_retention_sweep.sql` repeated.
--
-- ## The effective-list invariant
--
-- The `jobs.kind` allow-list in force is the one defined by the NEWEST
-- migration that defines it — this file, until a later migration redefines
-- the constraint again. Widening the set therefore means: copy the list
-- from the newest defining migration (027), add the new literal, and
-- append the result as the next numbered migration. Copying from an older
-- one silently narrows the set.
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
-- touches no privileges. The runtime DSN already holds the `DELETE` the
-- sweep needs: `008_api_tokens.sql` created the table under that same
-- convention, whose recipe is `GRANT SELECT, INSERT, UPDATE, DELETE ON
-- TABLES TO hort_app_role` (quoted in 009's header), so the grant is
-- table-level DML rather than per-statement and the sweep needs no new
-- one. `public.api_tokens` carries none of the mutation REVOKEs that make
-- `public.events` the exception to that convention.
--
-- Idempotence: the migration runs exactly once via the `_sqlx_migrations`
-- ledger, so the DROP carries no `IF EXISTS` — a missing `jobs_kind_check`
-- means the database's constraint set has diverged from this chain, and
-- the migration must fail loudly rather than mask that.
--
-- Expand/contract: this migration is purely additive — widening a CHECK
-- IN-list rejects nothing that was previously accepted — so it carries no
-- `migrations/CONTRACTIONS.toml` entry (ADR 0030). Row deletion is DML and
-- not DDL, so the sweep itself is outside that policy entirely.
--
-- Reversal (sqlx::migrate! is UP-only; no paired *.down.sql): drop
-- `jobs_kind_check` and re-add it over the list below minus
-- `'api-token-retention-sweep'`, after deleting any row already carrying
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
        'jobs-row-retention-sweep',
        -- The horizon on `public.api_tokens` — the first sweep in this
        -- family whose DELETE lands outside the task queue. Deletes rows
        -- whose own `expires_at` or `revoked_at` is more than 90 days in
        -- the past; a row with both NULL is a durable identity and
        -- matches neither disjunct. Enqueued once per tick by the
        -- `hort-server enqueue-api-token-retention-sweep` CronJob (and
        -- the matching systemd timer) on the runtime DSN, then claimed by
        -- the worker like any other task kind; also admin-invokable
        -- (present in `ADMIN_INVOKABLE_TASK_KINDS`), with no HTTP invoke
        -- route — the same posture as its three siblings, and for the
        -- same reason: a route would drag the `svc-token-bootstrap` chain
        -- to default-on.
        'api-token-retention-sweep'
    ));
