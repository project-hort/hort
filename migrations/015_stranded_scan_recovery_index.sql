-- Migration 015 — index for the stranded-scan recovery sweep (issue #6).
--
-- `RescanCandidatesRepository::select_stranded` (companion to
-- `select_eligible`) finds `quarantine_status='quarantined'` artifacts
-- whose most-recent `kind='scan'` job landed in `status='failed'` (a
-- scanner-execution failure that exhausted `HORT_SCANNER_MAX_ATTEMPTS`
-- retries — see `ScanOrchestrationUseCase::record_outcome`) and that have
-- no in-flight `kind='scan'` job, so the cron-rescan sweep can re-enqueue
-- a fresh scan once the scanner recovers.
--
-- The "most recent job for this artifact" half of that predicate is a
-- `LATERAL … ORDER BY created_at DESC LIMIT 1` per artifact row. This
-- partial index gives Postgres a direct index-scan for that lookup —
-- without it, the planner falls back to a sequential per-artifact filter
-- over every `kind='scan'` row on a table that grows without bound (every
-- scan attempt, across every retry, is its own row). The existing
-- "in-flight scan job" half of the predicate is already covered by the
-- `jobs_scan_unique` partial unique index from migration 009
-- (`(artifact_id) WHERE kind='scan' AND status IN ('pending','running')`).
--
-- Post-0.9.5 append-only rule (ADR 0022): a new numbered migration, not an
-- edit to migration 009.

CREATE INDEX idx_jobs_scan_artifact_created_at
    ON public.jobs (artifact_id, created_at DESC)
    WHERE kind = 'scan';
