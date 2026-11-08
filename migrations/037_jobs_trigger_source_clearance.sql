-- 037_jobs_trigger_source_clearance.sql
--
-- Redefines the `jobs.trigger_source` CHECK constraint so it admits
-- `'clearance'` — the trigger source the two **clearance-gating**
-- `provenance-verify` producers stamp: the signature-arrival hook
-- (`crates/hort-app/src/use_cases/ingest_use_case.rs`, the
-- `ingest_signature_manifest` S3 re-verify) and the window-expiry
-- backstop (`crates/hort-app/src/use_cases/quarantine_use_case.rs`,
-- `enqueue_final_provenance_verify`).
--
-- ## What the row could not say about itself
--
-- Both producers wrote `('provenance-verify', 'ingest')` because
-- `'ingest'` was the only literal the CHECK admitted that described
-- anything close. Two materially different pieces of work therefore
-- arrived on the queue indistinguishable:
--
--   * the **ingest-time** verify — one per ingest, so it IS the
--     backlog, and a client is waiting on their push becoming servable;
--   * the **clearance** verify — one per held artifact reaching its
--     window, and what waits on it is the release decision for an
--     artifact already held.
--
-- Everything that reads the row back — the tier derivation, the
-- ordinal, an audit of what the queue is spending itself on — saw an
-- ingest that is not one. The borrowing also forced the clearance
-- producers to name an ordinal literally at the call site, because the
-- pair the row carries cannot separate the two (ADR 0066 D6: no
-- producer names a number).
--
-- The CLASS does not change: both are `Interactive`, because who waits
-- does not change. What the literal buys is separation *within* the
-- class, by volume. Collapsing the two onto one ordinal instead would
-- make a held artifact wait behind the ingest-verify backlog, and that
-- is release latency.
--
-- ## Why a new numbered migration, not an edit of the newest definer
--
-- `sqlx::migrate!` validates the checksum of every applied migration,
-- so ANY edit to `036_jobs_trigger_source_register_by_hash.sql` — a
-- comment-only one included — makes an already-migrated database fail
-- its migrate step and refuse to boot. Widening the set is therefore
-- always an append: copy the list from the newest defining migration,
-- add the new literal, and append the result as the next numbered
-- migration. Same call `036` makes for `009`, and `018` for the
-- sibling `jobs.kind` constraint.
--
-- ## The effective-list invariant
--
-- The `jobs.trigger_source` allow-list in force is the one defined by
-- the NEWEST migration that defines it — this file, until a later
-- migration redefines the constraint again. 009's inline list and 036's
-- list are what a fresh install and a 036-era install respectively
-- started from; neither is the live list and neither must be read as
-- one.
--
-- The constraint is named explicitly, as 036 names it: 009 declares the
-- CHECK inline on the column, so PostgreSQL auto-names it
-- `jobs_trigger_source_check`, and re-adding it under that same name
-- keeps fresh and migrated installs on one stable identifier so the
-- next redefinition is not a name-guessing exercise.
--
-- ## One definition, and where it lives
--
-- The value set is defined once, in Rust, as
-- `hort_domain::ports::jobs_repository::TriggerSource` — its `ALL`
-- constant and its wildcard-free `as_str`, both generated from the one
-- `trigger_source_wire!` list. Every Rust consumer derives from it
-- (`FromStr`, serde, the tier/ordinal tables in
-- `hort_domain::types::task_tier`, and each writer's named
-- `*_TRIGGER_SOURCE` constant), and the list below is checked against
-- it by the DB-free lock-step guard
-- `crates/hort-adapters-postgres/tests/jobs_trigger_source_check_lockstep_guard.rs`,
-- which resolves the effective list exactly as defined above (newest
-- defining migration wins). The real-adapter enqueue proof iterates the
-- whole set against a fully-migrated database in
-- `crates/hort-adapters-postgres/tests/jobs_trigger_source_register_by_hash.rs`
-- (`every_trigger_source_literal_survives_the_jobs_check`), so this
-- literal is covered there without an edit.
--
-- Per-literal rationale lives with the Rust variants, and in 009's and
-- 036's annotated lists. The order below is 036's order with the new
-- literal appended, so a diff against 036 reads as one added line.
--
-- ## Not destructive DDL
--
-- The value set is **widened** and nothing loses its cover, so this is
-- outside ADR 0030's expand/contract arithmetic and needs no
-- `migrations/CONTRACTIONS.toml` entry (`expand_contract_guard` scans
-- for `DROP COLUMN` / `DROP TABLE` / RENAME / type change / `SET NOT
-- NULL`, none of which appear here). `no_sensitive_drops` exempts this
-- exact shape — a `DROP CONSTRAINT <name>_check` paired with an `ADD
-- CONSTRAINT` of the same `_check` name on the same table is an
-- enum-CHECK widening rather than a de-constrain — and the exemption is
-- `_check`-suffix-scoped and table-scoped, which this pairing
-- satisfies.
--
-- GRANTs / role wiring: none — the table already exists under the
-- post-004 default-privileges convention (ADR 0009); altering a CHECK
-- constraint touches no privileges.
--
-- Backfill: none, and none is possible. The clearance rows an older
-- binary wrote carry `'ingest'`, and nothing on them distinguishes a
-- clearance verify from an ingest-time one — that indistinguishability
-- is the defect. They drain as the `Interactive` rows they already
-- classify as, at the ordinal they already carry, and the separation
-- starts with the rows a current binary writes.
--
-- Idempotence: the migration runs exactly once via the
-- `_sqlx_migrations` ledger, so the DROP carries no `IF EXISTS` — a
-- missing `jobs_trigger_source_check` means the database's constraint
-- set has diverged from this chain, and the migration must fail loudly
-- rather than mask that (the same call `013_content_references_multivalue_pk.sql`
-- makes for its unguarded PK drop, and `018` / `036` for this exact
-- shape).
--
-- Reversal (sqlx::migrate! is UP-only; no paired *.down.sql): drop
-- `jobs_trigger_source_check` and re-add it over the list below minus
-- `'clearance'`, after rewriting any row already carrying that trigger
-- source to `'ingest'` — which is what the old binary wrote and what
-- its `queue_priority` arm reproduces, so no row's ordinal moves.

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
        'register-by-hash',
        -- The last thing between an artifact already held and a release
        -- decision: the signature-arrival re-verify and the
        -- window-expiry backstop. Distinct from `'ingest'`, which these
        -- two producers borrowed, because the ingest-time verify is one
        -- per ingest (it is the backlog) while a clearance verify is one
        -- per held artifact reaching its window — and a row that cannot
        -- say which it is cannot be ranked, audited or tiered as what it
        -- is.
        'clearance'
    ));
