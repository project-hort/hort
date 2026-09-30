-- 029_scan_findings_fixed_versions.sql
--
-- Store the source advisory's fixed versions in the per-finding projection
-- so retention's HasFixAvailable predicate can evaluate persisted scans.
-- The OSV producer and Finding::validate cap this array at 32 entries;
-- the CHECK keeps that bound for every writer.
--
-- Existing findings take the empty-array default and conservatively read
-- as having no known fix until a rescan replaces their projection data.
-- PostgreSQL 16 applies this non-volatile constant default as metadata,
-- without rewriting the populated table. Both additions are expansive;
-- no existing identifier is removed or narrowed (ADR 0030).

ALTER TABLE public.scan_findings
    ADD COLUMN fixed_versions text[] NOT NULL DEFAULT '{}'::text[];

ALTER TABLE public.scan_findings
    ADD CONSTRAINT scan_findings_fixed_versions_length
    CHECK (cardinality(fixed_versions) <= 32);
