-- Migration 026 -- durable per-artifact storage-purge work.
--
-- Removing an artifact's content-reference edges is irreversible: after the
-- DELETE, OCI membership targets cannot be reconstructed from the artifact
-- projection. Persisting every distinct target and its post-delete refcount in
-- the same transaction makes the storage work retryable without depending on
-- the deleted edges.
--
-- A NULL completed_at means the storage decision is still outstanding. For a
-- zero refcount that decision is a successful CAS delete; for a positive
-- refcount it is the decision to retain shared bytes. Rows remain until the
-- artifact's terminal events and deleted_at projection commit atomically.

CREATE TABLE public.artifact_purge_worklist (
    artifact_id     UUID        NOT NULL
        REFERENCES public.artifacts(id) ON DELETE CASCADE,
    content_hash    CHAR(64)    NOT NULL,
    refs_remaining  BIGINT      NOT NULL
        CHECK (refs_remaining >= 0 AND refs_remaining <= 4294967295),
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (artifact_id, content_hash),
    CONSTRAINT artifact_purge_worklist_hash_shape
        CHECK (content_hash ~ '^[0-9a-f]{64}$')
);

COMMENT ON TABLE public.artifact_purge_worklist IS
    'Durable per-hash work required before an artifact purge may retire its projection.';
