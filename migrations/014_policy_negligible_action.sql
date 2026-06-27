-- 014_policy_negligible_action.sql
--
-- Adds policy_projections.negligible_action — the operator knob steering how
-- negligible / informational advisories (RustSec unmaintained / unsound /
-- notice; carry no CVSS) affect the release decision:
--   'ignore' (default) — never block (informational != vulnerable);
--   'warn'             — record a PolicyEvaluated observation, do not block;
--   'block'            — reject (refuse unmaintained / unsound dependencies).
-- The scan evaluator reads this column through the policy projection.
--
-- Append-only ALTER per ADR 0022 (amended 2026-06-27): from 0.9.5 on, schema
-- changes are new altering migrations rather than in-place edits, because
-- pre-release deployments now run the applied schema and an in-place edit would
-- break their _sqlx_migrations checksums. DEFAULT 'ignore' backfills existing
-- rows, so every policy that predates the knob reads back as Ignore.

ALTER TABLE policy_projections
    ADD COLUMN negligible_action text NOT NULL DEFAULT 'ignore';

ALTER TABLE policy_projections
    ADD CONSTRAINT policy_projections_negligible_action_check
    CHECK (negligible_action = ANY (ARRAY['ignore'::text, 'warn'::text, 'block'::text]));
