-- Migration 010 — vulnerability re-scanning + advisory watch.
--
-- Adds the two projection tables that drive the rescanning + advisory
-- watch infrastructure:
--
--   * `sbom_components` — (artifact_id, purl, ecosystem, name, version)
--     reverse index. Populated alongside `scan_findings` in
--     `QuarantineUseCase::record_scan_result`. The advisory-watch tick
--     runs a `(ecosystem, name, version)` lookup against this table to
--     find the artifacts an OSV diff entry affects, then enqueues
--     `kind='scan'` jobs with `trigger_source='advisory'`.
--   * `advisory_sync_state` — single-row-per-feed pointer (`'osv'` for
--     v1; the column is `TEXT PRIMARY KEY` so future feeds add their own
--     row). Stores `last_sync_at` so the advisory watch tick pulls diffs
--     since the previous successful sync; updated atomically at the end
--     of the tick handler when (and only when) every per-ecosystem fetch
--     in the batch succeeded.
--
-- Why not also alter `public.jobs` here: migration 009 already carries
-- the final `jobs` shape with `kind`, `priority`, `trigger_source`, and
-- `result_summary` (folded in place — see 009's preamble). Pre-1.0,
-- schema-shape changes on existing tables are made in the original
-- migration in place rather than appended on top (ADR 0022). This
-- migration therefore only CREATEs new tables; if a future schema-shape
-- change is needed on `jobs`, the edit goes in 009 directly, not here.
--
-- GRANTs / role wiring: this migration ships NO explicit
-- `GRANT … TO hort_app_role` statements. The post-004 convention
-- (ADR 0009, mirrored from 005, 006, 007, 008) is that operators run
-- the role-bootstrap recipe before applying migrations, and
-- `ALTER DEFAULT PRIVILEGES` then auto-grants `SELECT, INSERT, UPDATE,
-- DELETE` on FUTURE tables created by `hort_admin`. Both new tables here
-- are exactly that case. See migrations/009_scan_jobs_and_findings.sql
-- §"GRANTs / role wiring" preamble — same convention.
--
-- Reversal: sqlx::migrate! runs UP-only; the project does not maintain
-- paired *.down.sql files. Manual reversal command if ever needed:
--
--   DROP TABLE IF EXISTS public.advisory_sync_state CASCADE;
--   DROP TABLE IF EXISTS public.sbom_components     CASCADE;
--
-- Pre-v1.0 (per `feedback_pre_release_migrations`): if the schema needs
-- adjusting before GA, edit THIS file in place rather than appending
-- 011_*_alter.sql on top.

-- ---------------------------------------------------------------------------
-- sbom_components (per-artifact SBOM reverse index)
-- ---------------------------------------------------------------------------
-- Columns:
--   * `artifact_id` — FK on `artifacts(id) ON DELETE CASCADE` so the
--     component rows disappear when their parent artifact is deleted.
--     The composite PK already orders `artifact_id` first, so the FK
--     rides the same index and adds no write amplification.
--   * `purl` — Package URL in canonical encoding (ecosystem-specific).
--     Kept as a separate stored column rather than synthesised from
--     `(ecosystem, name, version)` because OSV's PURL form has been
--     historically inconsistent across ecosystems (npm vs. PyPI vs.
--     Cargo); persisting the original purl lets the human-inspection
--     and direct-purl-lookup paths work without re-derivation.
--   * `ecosystem` / `name` / `version` — typed columns matching the
--     OSV diff entry shape. The `(ecosystem, name)` index drives the
--     advisory-watch DISTINCT-artifact_id query:
--
--       SELECT DISTINCT artifact_id
--       FROM sbom_components
--       WHERE ecosystem = $1 AND name = $2 AND version = ANY($3::text[]);
--
--     `version` is NULL-able because some SBOM entries (especially
--     transitive dependencies in incomplete SBOMs) lack a resolved
--     version. The advisory-watch query uses `version = ANY(...)`
--     which evaluates to NULL (filtered out by `WHERE`) on those
--     rows — they are never reported as affected.

CREATE TABLE public.sbom_components (
    artifact_id UUID NOT NULL REFERENCES public.artifacts(id) ON DELETE CASCADE,
    purl        TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT,
    PRIMARY KEY (artifact_id, purl)
);

-- Lookup-by-purl path (operator inspection, direct-purl rescans).
CREATE INDEX sbom_components_purl_idx
    ON public.sbom_components (purl);

-- Drives the advisory-watch DISTINCT-artifact_id query.
CREATE INDEX sbom_components_ecosystem_name_idx
    ON public.sbom_components (ecosystem, name);

-- ---------------------------------------------------------------------------
-- advisory_sync_state (per-feed sync pointer)
-- ---------------------------------------------------------------------------
-- Columns:
--   * `feed` — PRIMARY KEY. The v1 deployment carries one row,
--     `feed='osv'`. The column is `TEXT` (not an enum) so future
--     feeds — GitHub Advisory, vendor-specific feeds — add their own
--     row without a schema migration.
--   * `last_sync_at` — high-water mark of the previous successful
--     bulk-pull. The advisory-watch tick reads this, calls
--     `AdvisoryPort::pull_diff_since(last_sync_at)`, processes every
--     ecosystem, and (only when ALL per-ecosystem fetches succeed)
--     UPDATEs `last_sync_at = now()`. Partial failure leaves the
--     value behind so the next tick re-attempts the missed window.
--   * `last_error` — populated when the most recent tick produced a
--     handler-level failure; cleared on the next successful tick.
--     NULL on first install (the seed row leaves it unset).
--   * `updated_at` — write-time of the last UPDATE on this row.

CREATE TABLE public.advisory_sync_state (
    feed         TEXT PRIMARY KEY,
    last_sync_at TIMESTAMPTZ NOT NULL,
    last_error   TEXT,
    updated_at   TIMESTAMPTZ NOT NULL
);

-- Seed the OSV row at install time.
--
-- Why `now() - interval '24 hours'` and not `now()`: the first
-- advisory-watch tick after install must process a meaningful diff
-- window. Seeding at `now()` would make the first tick a zero-width
-- diff (no entries with `modified_at > now()`) and silently miss
-- whatever OSV published between the install moment and the first
-- scheduled tick — typically several hours later under the default
-- `0 */6 * * *` schedule. The 24-hour offset gives the first tick a
-- meaningful backfill window.
--
-- `ON CONFLICT DO NOTHING` keeps the migration idempotent: re-running
-- on a database that already has the seed row is a no-op (existing
-- `last_sync_at` is preserved — the seed is for cold start only).
INSERT INTO public.advisory_sync_state (feed, last_sync_at, updated_at)
VALUES ('osv', now() - INTERVAL '24 hours', now())
ON CONFLICT DO NOTHING;
