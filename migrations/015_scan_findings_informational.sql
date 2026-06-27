-- 015_scan_findings_informational.sql
--
-- Adds scan_findings.informational_class — the raw OSV
-- database_specific.informational class string verbatim (RustSec
-- unmaintained / unsound / notice), or NULL for a scored vulnerability.
-- This persists the FACT the advisory database published, not a derived
-- boolean interpretation: a finding reconstructed from this projection
-- (e.g. exclusion-triggered re-evaluation) re-derives the informational
-- boolean and the non-enforcing negligible-lane routing (steered by
-- policy_projections.negligible_action) under the current — or any future
-- per-class — policy. A baked-in boolean would have lost the class and
-- frozen the interpretation. Without the column the reconstructed finding
-- reads back NULL (a scored vulnerability), so under
-- negligible_action='block' a finding blocked at scan time would silently
-- fail to re-block.
--
-- Append-only ALTER per ADR 0022 (amended 2026-06-27): from 0.9.5 on,
-- schema changes are new altering migrations rather than in-place edits,
-- because pre-release deployments now run the applied schema and an
-- in-place edit would break their _sqlx_migrations checksums. The column
-- is nullable with no default, so every finding that predates the column
-- reads back NULL — a scored vulnerability, the prior behaviour.

ALTER TABLE scan_findings
    ADD COLUMN informational_class text;
