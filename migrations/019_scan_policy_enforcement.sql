-- Migration 019 — `ScanPolicy.enforcement` (reject | record).
--
-- A scan policy's threshold knobs (`severity_threshold`, `license_policy`,
-- `negligible_action`) decide WHICH findings are enforcement-worthy. This
-- column decides what the resulting verdict is allowed to DO to the
-- artifact:
--   'reject' (default) — a blocking verdict rejects the artifact
--                        (`PolicyEvaluated(Fail)` + `ArtifactRejected`);
--                        downloads are blocked by the `rejected` status.
--                        This is the behaviour of every policy written
--                        before this column existed.
--   'record'           — the scan still runs, the per-finding rows and the
--                        `PolicyEvaluated(Fail)` verdict are still written,
--                        and the artifact is NOT rejected. Publication
--                        proceeds with findings; blocking at retrieval is
--                        the consuming policy's job.
--
-- The `DEFAULT 'reject'` is load-bearing, not cosmetic: it is what makes
-- this an additive column for every existing row (each was written under
-- enforcing semantics, so 'reject' is the honest backfill) and it mirrors
-- `ScanEnforcement::default()` in the domain layer.
--
-- The scan evaluator and the policy re-evaluation decision point both read
-- this column through the policy projection, in both directions: a
-- 'record' -> 'reject' change re-derives the in-scope population's
-- verdicts from stored findings and re-holds the now-non-compliant ones,
-- and 'reject' -> 'record' un-rejects them (ADR 0041).

ALTER TABLE public.policy_projections
    ADD COLUMN enforcement text DEFAULT 'reject' NOT NULL;

-- enforcement is one of the two wire values (mirrors the
-- negligible_action / provenance_mode CHECK shape in 005_policy.sql).
ALTER TABLE public.policy_projections
    ADD CONSTRAINT policy_projections_enforcement_check CHECK (
        (enforcement = ANY (ARRAY['reject'::text, 'record'::text]))
    );
