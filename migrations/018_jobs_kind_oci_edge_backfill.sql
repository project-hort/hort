-- 018_jobs_kind_oci_edge_backfill.sql
--
-- Redefines the `jobs.kind` CHECK constraint so it admits
-- `'oci-membership-edge-backfill'` — the one-shot admin task kind consumed
-- by `OciMembershipEdgeBackfillHandler`
-- (`crates/hort-app/src/task_handlers/oci_membership_edge_backfill.rs`).
-- The task walks OCI single-image manifest rows that carry no `oci_config`
-- `content_references` edge (rows minted before the write path registered
-- membership edges on every manifest PUT / pull-through), re-derives the
-- missing `oci_config` / `oci_layer` edges from the manifest's own stored
-- bytes, and so restores GC keepalive for blobs reachable only through
-- such a row.
--
-- ## Why a new numbered migration, not an edit of 009's inline list
--
-- ADR 0022's controlling principle is "no in-place edit once you can't
-- wipe". Databases that cannot be wiped now exist (they hold real
-- published artifacts), so `009_scan_jobs_and_findings.sql` is frozen:
-- `sqlx::migrate!` validates the checksum of every applied migration, and
-- ANY edit to that file — a comment-only one included — makes an
-- already-migrated database fail its migrate step with `VersionMismatch`
-- and refuse to boot. (009's own inline comment still describes the
-- superseded in-place practice; it cannot be corrected in place for
-- exactly that reason. This file is the correction.)
--
-- The freeze is decisive for this kind in particular: the backfill only
-- has work to do on already-migrated databases — legacy rows are by
-- definition rows such a database already holds — i.e. precisely the
-- installs an in-place widening of 009 never reaches.
--
-- ## The effective-list invariant
--
-- The `jobs.kind` allow-list in force is the one defined by the NEWEST
-- migration that defines it — this file, until a later migration
-- redefines the constraint again. 009's inline list is only what a fresh
-- install starts from; it is not the live list and must not be read as
-- one. Widening the set therefore means: copy the list from the newest
-- defining migration, add the new literal, and append the result as the
-- next numbered migration.
--
-- The constraint is named explicitly here. 009 declares the CHECK inline
-- on the column, so PostgreSQL auto-names it `jobs_kind_check`; re-adding
-- it under that same name gives fresh and migrated installs one stable
-- identifier, so the next redefinition is not a name-guessing exercise.
--
-- Keep this list in lock-step with `hort_domain::events::EVENT_TASK_KINDS`
-- (`crates/hort-domain/src/events/authorization_events.rs`); per-kind
-- rationale lives with that constant and in 009's annotated list. The
-- DB-free structural guard
-- `crates/hort-adapters-postgres/tests/task_kind_check_lockstep_guard.rs`
-- resolves the effective list exactly as defined above (newest defining
-- migration wins) and fails when the two sides drift. The real-adapter
-- enqueue proof for the new kind is
-- `crates/hort-adapters-postgres/tests/jobs_kind_check_oci_edge_backfill.rs`.
--
-- GRANTs / role wiring: none — the table already exists under the post-004
-- default-privileges convention (ADR 0009); altering a CHECK constraint
-- touches no privileges.
--
-- Idempotence: the migration runs exactly once via the `_sqlx_migrations`
-- ledger, so the DROP carries no `IF EXISTS` — a missing `jobs_kind_check`
-- means the database's constraint set has diverged from this chain, and
-- the migration must fail loudly rather than mask that (the same call
-- `013_content_references_multivalue_pk.sql` makes for its unguarded PK
-- drop).
--
-- Reversal (sqlx::migrate! is UP-only; no paired *.down.sql): drop
-- `jobs_kind_check` and re-add it over the list below minus
-- `'oci-membership-edge-backfill'`, after deleting any row already
-- carrying that kind.

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
        -- Membership-edge retrofit for legacy OCI manifest rows: manual
        -- admin-task invocation only, no recurring schedule.
        'oci-membership-edge-backfill'
    ));
