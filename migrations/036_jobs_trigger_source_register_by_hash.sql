-- 036_jobs_trigger_source_register_by_hash.sql
--
-- Redefines the `jobs.trigger_source` CHECK constraint so it admits
-- `'register-by-hash'` — the trigger source
-- `IngestUseCase::register_by_hash` stamps on the scan / provenance-verify
-- rows it enqueues when the caller supplies no quarantine-anchor override
-- (`crates/hort-app/src/use_cases/ingest_use_case.rs`). Those callers are
-- the OCI cross-repository blob mount
-- (`crates/hort-http-oci/src/uploads.rs::handle_cross_mount`) and the
-- cross-repository pull-dedup followers; the seed import, which does
-- supply an anchor, stamps `'seed-import'` instead.
--
-- ## The reachable consequence this closes
--
-- `POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<repo>` answered
-- `500` whenever the target repository's scan policy requested a scan for
-- the mounted blob. `enqueue_scan_in_tx` binds the trigger source
-- verbatim, the insert rides inside the ingest transition's transaction,
-- and the CHECK violation therefore aborted the whole transition —
-- surfacing through `map_register_error`'s catch-all as
-- `OciError::Internal`. The OCI Distribution Spec admits `201` (mounted)
-- or `202` (fall back to a normal upload) here and nothing else, so the
-- client had no way to degrade. The path only functioned where no
-- `scan_backends` were configured, i.e. precisely where nothing was
-- scanned.
--
-- ## Why a new numbered migration, not an edit of 009's inline list
--
-- Same reason `018_jobs_kind_oci_edge_backfill.sql` gives for the sibling
-- `jobs.kind` constraint: databases that cannot be wiped exist, and
-- `sqlx::migrate!` validates the checksum of every applied migration, so
-- ANY edit to `009_scan_jobs_and_findings.sql` — a comment-only one
-- included — makes an already-migrated database fail its migrate step and
-- refuse to boot. 009's own inline comments still describe the superseded
-- in-place practice ("Added in place per ADR 0022; DB MUST be
-- re-migrated"); they cannot be corrected in place for exactly that
-- reason. This file is the correction for this column.
--
-- The freeze is decisive here rather than incidental: the mount's `500`
-- is reachable on an already-migrated database, which is precisely the
-- install an in-place widening of 009 never reaches.
--
-- ## The effective-list invariant
--
-- The `jobs.trigger_source` allow-list in force is the one defined by the
-- NEWEST migration that defines it — this file, until a later migration
-- redefines the constraint again. 009's inline list is only what a fresh
-- install starts from; it is not the live list and must not be read as
-- one. Widening the set therefore means: copy the list from the newest
-- defining migration, add the new literal, and append the result as the
-- next numbered migration.
--
-- The constraint is named explicitly here. 009 declares the CHECK inline
-- on the column, so PostgreSQL auto-names it
-- `jobs_trigger_source_check`; re-adding it under that same name gives
-- fresh and migrated installs one stable identifier, so the next
-- redefinition is not a name-guessing exercise.
--
-- ## One definition, and where it lives
--
-- The value set is defined once, in Rust, as
-- `hort_domain::ports::jobs_repository::TriggerSource` — its `ALL`
-- constant and its wildcard-free `as_str`. Every Rust consumer derives
-- from it (`FromStr`, serde, the tier/ordinal tables in
-- `hort_domain::types::task_tier`, and each writer's named
-- `*_TRIGGER_SOURCE` constant), and the list below is checked against it
-- by the DB-free lock-step guard
-- `crates/hort-adapters-postgres/tests/jobs_trigger_source_check_lockstep_guard.rs`,
-- which resolves the effective list exactly as defined above (newest
-- defining migration wins). The real-adapter enqueue proof for the new
-- literal is
-- `crates/hort-adapters-postgres/tests/jobs_trigger_source_check_register_by_hash.rs`;
-- the end-to-end mount proof is
-- `crates/hort-server/tests/oci_cross_mount_scan_enqueue_real_db.rs`.
--
-- Per-literal rationale lives with the Rust variants and in 009's
-- annotated list. The order below is 009's order with the new literal
-- appended, so a diff against 009 reads as one added line.
--
-- ## Not destructive DDL
--
-- The value set is **widened** and nothing loses its cover, so this is
-- outside ADR 0030's expand/contract arithmetic and needs no
-- `migrations/CONTRACTIONS.toml` entry (`expand_contract_guard` scans for
-- `DROP COLUMN` / `DROP TABLE` / RENAME / type change / `SET NOT NULL`,
-- none of which appear here). `no_sensitive_drops` exempts this exact
-- shape — a `DROP CONSTRAINT <name>_check` paired with an `ADD
-- CONSTRAINT` of the same `_check` name on the same table is an enum-CHECK
-- widening rather than a de-constrain — and the exemption is
-- `_check`-suffix-scoped and table-scoped, which this pairing satisfies.
--
-- GRANTs / role wiring: none — the table already exists under the
-- post-004 default-privileges convention (ADR 0009); altering a CHECK
-- constraint touches no privileges.
--
-- Backfill: none. No existing row can carry `'register-by-hash'` — the
-- old CHECK refused it, which is the defect — so there is nothing to
-- migrate. Rows that WERE written before this migration are the ones
-- whose transaction aborted, i.e. none.
--
-- Idempotence: the migration runs exactly once via the `_sqlx_migrations`
-- ledger, so the DROP carries no `IF EXISTS` — a missing
-- `jobs_trigger_source_check` means the database's constraint set has
-- diverged from this chain, and the migration must fail loudly rather
-- than mask that (the same call `013_content_references_multivalue_pk.sql`
-- makes for its unguarded PK drop, and `018` for this exact shape).
--
-- Reversal (sqlx::migrate! is UP-only; no paired *.down.sql): drop
-- `jobs_trigger_source_check` and re-add it over the list below minus
-- `'register-by-hash'`, after deleting any row already carrying that
-- trigger source. Note that doing so re-opens the mount's `500`.

ALTER TABLE public.jobs
    DROP CONSTRAINT jobs_trigger_source_check;

ALTER TABLE public.jobs
    ADD CONSTRAINT jobs_trigger_source_check CHECK (trigger_source IN (
        'manual',
        'cron',
        'advisory',
        'ingest',
        'seed-import',
        'prefetch',
        'self_service',
        'scheduled',
        -- Per-repository row minted over content already in CAS with no
        -- backdated anchor: the OCI cross-repository blob mount and the
        -- cross-repository pull-dedup followers. Distinct from
        -- `'ingest'` because the caller class is what separates a mount
        -- or a coalesced follower from an ordinary ingest in the audit
        -- trail, and distinct from `'seed-import'`, which is the same
        -- entry point with an operator-supplied backdated anchor.
        'register-by-hash'
    ));
