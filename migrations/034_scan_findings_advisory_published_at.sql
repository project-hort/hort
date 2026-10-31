-- 034_scan_findings_advisory_published_at.sql
--
-- Store the source advisory's publication date in the per-finding
-- projection so retention's HasFindingDetectedFor predicate can anchor on
-- how long the VULNERABILITY has been known rather than on how long this
-- artifact happens to have been scanned. The upstream date is the only
-- source that dates the vulnerability itself; an anchor taken from the
-- artifact's own scan history dates when we started looking, and a
-- predicate that deletes must not read the second as the first.
--
-- Nullable with no default, and deliberately not backfilled: the date is
-- a fact about an advisory that only the producing backend can supply, so
-- there is nothing in this schema to derive it from. A NULL reads back as
-- "no backend published a date for this finding", and the anchor then
-- falls to MIN(detected_at) for the same (artifact_id, vulnerability_id)
-- — our own first observation, which is strictly later than publication
-- and so strictly less likely to expire anything. Existing rows take
-- NULL until a rescan replaces their projection data.
--
-- Expansive: no existing identifier is removed or narrowed (ADR 0030).
-- Adding a nullable column with no default is catalog-only in
-- PostgreSQL 16 — no table rewrite on a populated projection.

ALTER TABLE public.scan_findings
    ADD COLUMN advisory_published_at timestamptz;
