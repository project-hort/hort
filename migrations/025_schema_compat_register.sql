-- 025_schema_compat_register.sql
--
-- The schema compatibility register: one row per applied migration,
-- carrying the oldest binary version that migration tolerates.
--
-- ## Why the schema has to carry this
--
-- An older binary fails against a newer schema for exactly one reason:
-- among the applied migrations it does not embed, one was a contraction
-- that removed an identifier the binary still references (ADR 0030).
-- Expansions are harmless however many of them there are, so a fixed
-- "one release back" rollback bound refuses rollbacks that are provably
-- safe.
--
-- `migrations/CONTRACTIONS.toml` already records, per destructive
-- migration, the release whose code stopped referencing the identifiers
-- it removes (`reference_removed_in`) — which is precisely the oldest
-- binary version that migration tolerates. A binary can read that
-- manifest only for the migrations it embeds, and the migrations a
-- rollback cares about are exactly the ones it does not. So the answer
-- is written into the database by the binary that applies the migration,
-- and read back by any later (or earlier) binary.
--
-- ## Columns
--
--   version             the sqlx migration version (the leading integer of
--                       the migration file name), matching
--                       `_sqlx_migrations.version`. No foreign key: this
--                       table must not take a dependency on sqlx's own
--                       bookkeeping table, whose shape sqlx owns.
--   min_binary_version  the oldest binary version that tolerates this
--                       migration, as a plain `X.Y.Z`. NULL means the
--                       migration is an expansion — it removed nothing, so
--                       every binary tolerates it. A non-NULL value is the
--                       migration's `reference_removed_in` from
--                       `migrations/CONTRACTIONS.toml`.
--   recorded_at         when the row was written, for incident forensics.
--
-- ## Why not extend `_sqlx_migrations`
--
-- That table belongs to sqlx: its columns, checksum semantics and
-- create-if-missing DDL are library-owned, and `sqlx::migrate!` validates
-- it on every run. A hort-owned column on it would be a private extension
-- of somebody else's schema, breakable by a dependency bump.
--
-- ## Absence is not evidence
--
-- A row is written only by a binary that ships the migration it describes,
-- so rows exist only from the release that introduced this table onwards.
-- The boot gates therefore treat an applied-but-unembedded migration with
-- no row here as a contraction requiring a version the binary does not
-- have (`hort_config::schema_compat`). That fail-closed rule is also what
-- makes bootstrapping self-resolving: a rollback target predating this
-- table has no register logic at all and uses the strict structural gate,
-- and every binary that does have the logic embeds every migration up to
-- and including this one.
--
-- ## Write path / role wiring
--
-- Rows are written by `hort-server migrate` only, in the same operation
-- that applies the migration, under the DDL role. The serve path reads
-- this table with a bare `SELECT` and issues no DDL (ADR 0009).
--
-- GRANTs: none explicit. The post-004 convention (ADR 0009, mirrored from
-- 005 onwards) is that operators run the role-bootstrap recipe before
-- applying migrations, and `ALTER DEFAULT PRIVILEGES` then auto-grants
-- `SELECT, INSERT, UPDATE, DELETE` on future tables created by
-- `hort_admin`. This table is exactly that case.
--
-- Reversal (sqlx::migrate! is UP-only; no paired *.down.sql): drop the
-- table. Doing so re-arms the fail-closed rule for every rollback, but
-- breaks nothing that is running.

CREATE TABLE public.schema_compat_register (
    version            BIGINT      PRIMARY KEY,
    min_binary_version TEXT,
    recorded_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- A recorded minimum is a plain `X.Y.Z`, the same shape
    -- `CONTRACTIONS.toml`'s `reference_removed_in` carries and the same
    -- shape `hort_config::pg_identity::parse_version_core` compares. The
    -- constraint rejects an empty string, which would parse as "unknown"
    -- and silently fail the row closed.
    CONSTRAINT schema_compat_register_min_binary_version_shape
        CHECK (min_binary_version IS NULL OR min_binary_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$')
);

COMMENT ON TABLE public.schema_compat_register IS
    'Oldest binary version each applied migration tolerates. NULL min_binary_version = expansion.';
