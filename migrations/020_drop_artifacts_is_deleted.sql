-- Migration 020 — drop the inert `artifacts.is_deleted` column.
--
-- `is_deleted` was declared as a soft-delete flag but was never written
-- outside test fixtures: artifact deletion is a hard `DELETE FROM artifacts`,
-- so no row has ever carried `is_deleted = true`. Every `is_deleted = false`
-- predicate in the read path was therefore a no-op, and both partial indexes
-- predicated on it covered the whole table anyway.
--
-- The column is removed rather than the filters completed, because
-- `artifacts_repository_id_path_key UNIQUE (repository_id, path)` makes a
-- surviving soft-deleted row keep occupying its path: hiding such a row from
-- the ingest lookup (`find_by_path`) would drive the follow-up insert into a
-- constraint violation. With the column gone, that lookup's unfiltered read is
-- consistent with every other read by construction rather than by convention.

ALTER TABLE public.artifacts DROP COLUMN is_deleted;

-- Postgres drops any index that references a dropped column, so both partial
-- indexes above went with it. Recreate them with the same key columns and the
-- same INCLUDE payload, minus the predicate — the predicate selected the whole
-- table, so a plain index is the same set of entries.

CREATE INDEX idx_artifacts_name_as_published
    ON public.artifacts USING btree (repository_id, name_as_published);

-- Covering index for the per-(package, version) servability query
-- (`ArtifactRepository::package_version_status`), the hot read path of the
-- quarantine-aware index-serve filter. An npm/PyPI/Cargo/Maven index
-- resolution fires this query dozens to hundreds of times per `install`; the
-- served-document filter cannot afford a heap fetch per match.
-- `(repository_id, name)` is the lookup key; `INCLUDE (version,
-- quarantine_status)` keeps the row payload in the leaf so Postgres plans an
-- index-only scan with no heap visit. This is the highest-QPS query in the
-- servability path and the single most important optimisation on it.
CREATE INDEX idx_artifacts_repo_name_status_covering
    ON public.artifacts USING btree (repository_id, name)
    INCLUDE (version, quarantine_status);
