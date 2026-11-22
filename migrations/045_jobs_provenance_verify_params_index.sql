-- 045_jobs_provenance_verify_params_index.sql
--
-- Partial expression index for the expiry backstop's in-flight
-- `provenance-verify` lookup. `JobsRepository::find_active_provenance_for_artifact`
-- reads the artifact id from `params` and matches only pending or running jobs.
--
-- ## Why this index is partial
--
-- `jobs` is the highest-write-rate table in the schema. Only in-flight
-- provenance-verification rows belong in this index: their number is bounded
-- by fleet concurrency, not by table size. A whole-table expression index
-- would grow with completed job history and add write cost to every job kind.
--
-- ## Why this index is not unique
--
-- The expiry backstop uses the in-flight read to skip a second enqueue. A
-- unique index would instead turn a second enqueue into a constraint error
-- and narrow the write contract, which requires a later release under
-- ADR 0030. This index only speeds the existing read.
--
-- ## Why a new numbered migration
--
-- ADR 0022: sqlx validates the checksum of every applied migration, so even
-- a comment-only edit to an old migration can prevent an existing database
-- from booting. This additive, non-unique `CREATE INDEX` names no identifier
-- that previous-release code could lose and narrows no write contract, so it
-- needs no `CONTRACTIONS.toml` entry.
--
-- The ordinary index build takes a write lock on `jobs` for the duration of
-- one table scan. It runs in the boot migration hook, so no operator action
-- follows from it. The build cannot use `CONCURRENTLY` because sqlx runs
-- migrations inside a transaction.

CREATE INDEX IF NOT EXISTS jobs_provenance_verify_artifact_idx
    ON public.jobs ((params->>'artifact_id'))
    WHERE kind = 'provenance-verify' AND status IN ('pending', 'running');
