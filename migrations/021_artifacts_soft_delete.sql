-- Migration 021 — artifact deletion becomes an event-sourced soft-delete.
--
-- Deleting an artifact used to be a bare `DELETE FROM artifacts`: the one
-- terminal artifact-lifecycle transition that left no trace in the event
-- log and no row to audit. Deletion now emits `ArtifactDeleted` on the
-- artifact's own stream and *retains* the row, marked by the `deleted_at`
-- column this migration adds. `deleted_at IS NULL` means live; non-NULL
-- means deleted. The CAS blob is untouched — blob lifetime stays
-- refcount-gated GC, because another artifact may reference the same bytes.
--
-- Deletion is deliberately NOT a `quarantine_status` value: it is
-- orthogonal to the scan axis (a released artifact and a rejected one are
-- both deletable), and folding the two axes together would destroy the
-- pre-deletion status an auditor needs.
--
-- ## Why the path uniqueness becomes a partial index
--
-- `artifacts_repository_id_path_key UNIQUE (repository_id, path)` made a
-- retained row keep occupying its path forever: hiding a soft-deleted row
-- from the ingest lookup would then drive the follow-up insert straight
-- into a constraint violation. That hazard is why the earlier
-- `is_deleted` flag was removed instead of completed. Predicating the
-- uniqueness on `deleted_at IS NULL` resolves it: a deleted row no longer
-- reserves its path, so a fresh ingest at the same path succeeds and mints
-- a NEW artifact (new id, new row, new stream) while the deleted one stays
-- readable as history.
--
-- ## Why the two read-path indexes become partial again
--
-- Both were partial on the removed flag and were rebuilt as plain indexes
-- when it went away, because the predicate then selected the whole table.
-- With a real soft-delete tail they select a strict subset again, and —
-- more importantly — every live read now carries `deleted_at IS NULL`.
-- `idx_artifacts_repo_name_status_covering` backs the per-(package,
-- version) servability query, the highest-QPS read in the index-serve
-- path; without the matching predicate the planner can no longer satisfy
-- that query from the index leaf and would add a heap fetch per matched
-- row. Restoring the predicate keeps it an index-only scan.

ALTER TABLE public.artifacts
    ADD COLUMN deleted_at timestamp with time zone;

-- Path uniqueness among LIVE rows only (see the header rationale).
ALTER TABLE public.artifacts
    DROP CONSTRAINT artifacts_repository_id_path_key;

CREATE UNIQUE INDEX artifacts_repository_id_path_live_key
    ON public.artifacts USING btree (repository_id, path)
    WHERE (deleted_at IS NULL);

-- Name-lookup index: matches `find_by_name_as_published`'s predicate.
DROP INDEX public.idx_artifacts_name_as_published;

CREATE INDEX idx_artifacts_name_as_published
    ON public.artifacts USING btree (repository_id, name_as_published)
    WHERE (deleted_at IS NULL);

-- Covering index for the per-(package, version) servability query
-- (`ArtifactRepository::package_version_status`). `(repository_id, name)`
-- is the lookup key; `INCLUDE (version, quarantine_status)` keeps the row
-- payload in the leaf so Postgres plans an index-only scan with no heap
-- visit. The `deleted_at IS NULL` predicate must mirror the query's own
-- filter exactly or that plan degrades to an index scan plus heap fetch.
DROP INDEX public.idx_artifacts_repo_name_status_covering;

CREATE INDEX idx_artifacts_repo_name_status_covering
    ON public.artifacts USING btree (repository_id, name)
    INCLUDE (version, quarantine_status)
    WHERE (deleted_at IS NULL);
