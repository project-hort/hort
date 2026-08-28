-- Migration 022 — fair candidacy for the quarantine-release sweep.
--
-- The sweep selects up to a fixed batch of quarantined artifacts whose
-- observation window has elapsed, then re-checks release authority per
-- candidate. Candidacy used to be ordered by `quarantine_window_start`
-- alone, so the oldest rows were re-selected on every tick — and a
-- candidate the authority or provenance gate permanently holds (the
-- canonical case: a config/layer blob whose clearance can only ever come
-- from its parent manifest's cascade) is never released and never leaves
-- that position. Once such rows filled a whole batch, the sweep stopped
-- reaching ANY other artifact in the deployment: nothing was released
-- again, indefinitely, with no error anywhere.
--
-- `release_attempt_at` breaks that fixed point. It records only WHEN the
-- sweep last considered the row, never WHAT it decided, and the sweep
-- stamps the whole batch each tick. Ordering by it (NULLS FIRST) makes
-- candidacy a rotation: a never-attempted artifact is served on the very
-- next tick regardless of backlog size, and a backlog of N is fully
-- re-attempted every ceil(N / batch) ticks.
--
-- ## Why this column is not event-sourced
--
-- It is operational scheduling metadata, in the same class as the task
-- queue's own scheduling columns — not lifecycle state. The artifact's
-- lifecycle stays exactly the events on its stream
-- (`ArtifactQuarantined`, `ScanCompleted`, `ArtifactReleased`, …); a
-- replay that ignores this column reconstructs the identical artifact.
-- Emitting an event per attempt would write one immutable audit record
-- per candidate per five-minute tick forever while carrying no decision,
-- and would make the scheduler a producer of lifecycle history.
--
-- Candidacy/authority layering is unchanged: candidacy remains "window
-- elapsed" in SQL, authority remains the fail-closed per-artifact check
-- in the application layer. This column only reorders *which* candidates
-- a bounded batch gets to re-check first; it can never authorize a
-- release.

ALTER TABLE public.artifacts
    ADD COLUMN release_attempt_at timestamp with time zone;

-- The candidacy index moves from the window anchor to the (cursor,
-- anchor) pair so the sweep's ORDER BY is satisfied by the index itself
-- rather than by a sort over the whole quarantined set. Column order
-- mirrors the query's ORDER BY exactly — including `NULLS FIRST`, which
-- is NOT the ASC default and must be spelled out for the index to serve
-- the ordering.
--
-- The window anchor stays as the second key, so the range predicate
-- (`quarantine_window_start <= now() - D`) still filters inside the
-- index, and among equally-stale candidates the oldest window is still
-- served first. The single-column predecessor
-- (`idx_artifacts_quarantine_window_start`) had exactly one consumer —
-- this sweep — and is fully subsumed here, so it is replaced rather than
-- kept alongside.
DROP INDEX public.idx_artifacts_quarantine_window_start;

CREATE INDEX idx_artifacts_quarantine_release_cursor
    ON public.artifacts USING btree (release_attempt_at ASC NULLS FIRST, quarantine_window_start ASC)
    WHERE (((quarantine_status)::text = 'quarantined'::text) AND (quarantine_window_start IS NOT NULL));

COMMENT ON COLUMN public.artifacts.release_attempt_at IS
    'When the quarantine-release sweep last attempted this artifact. Operational scheduling metadata, deliberately not event-sourced: it records that a decision was attempted, never what the decision was. Ordering candidacy by it (NULLS FIRST) stops a permanently-unreleasable candidate from occupying the batch head forever and starving the rest of the backlog.';
