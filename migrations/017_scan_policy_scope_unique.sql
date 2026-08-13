-- Migration 017 — at most one active ScanPolicy per scope.
--
-- `policy_projections.scope` (jsonb) discriminates `Global` from
-- `Repository(<repository_id>)` (see `PgPolicyProjectionRepository`'s
-- module docs, `crates/hort-adapters-postgres/src/policy_projection_repo.rs`,
-- for the authoritative shape): `PolicyScope` round-trips through serde's
-- default externally-tagged representation, so a `Global` row's column
-- value is the bare JSON string `"Global"` and a `Repository(id)` row's
-- value is the single-key object `{"Repository": "<uuid>"}`.
--
-- Nothing at the storage layer stopped two non-archived rows from
-- occupying the same scope — the runtime policy resolver and the
-- trust_upstream_publish_time x scan_backends apply-time linter both
-- assume at most one active policy per scope, and had no ordering
-- guarantee to fall back on if that assumption broke. The gitops apply
-- path now rejects this before it ever reaches a projection write, but
-- that is one write path among however many have existed over this
-- table's history — this index is the structural backstop that holds
-- regardless of caller.
--
-- `scope->>'Repository'` extracts the repository id as text (NULL for a
-- `Global` row, since `->>` on a non-object jsonb value or a missing key
-- returns NULL rather than erroring); `COALESCE(..., 'Global')` folds
-- every `Global` row onto one non-NULL sentinel so they collide under
-- standard UNIQUE semantics instead of each being treated as a distinct
-- NULL (Postgres UNIQUE indexes treat NULL values as mutually
-- non-equal — the whole reason a plain `UNIQUE (scope)` would silently
-- let unlimited `Global` rows through even though it enforced
-- `Repository` uniqueness). `'Global'` can never collide with a real
-- repository id (a UUID's text form), so this is a safe combined
-- discriminator, not just a coincidental non-clash. Both operators used
-- are IMMUTABLE, so the expression is index-safe.
--
-- Idempotent data-fix UPDATE before the index is created: keep the
-- earliest (`created_at`, then `policy_id` as the deterministic
-- tie-break) non-archived row per scope and archive the rest. This is a
-- projection-only repair — it does not append a matching `PolicyArchived`
-- event, so the affected row's event stream stays as history recorded it;
-- that divergence is accepted here because a migration has no event-store
-- handle to append through, and only a row that could not legally have
-- been created via the current application code paths would ever be
-- touched. The WHERE-guarded scope of the ranking (`archived = false`)
-- makes this UPDATE a no-op wherever no such row exists.
WITH ranked AS (
    SELECT policy_id,
           row_number() OVER (
               PARTITION BY COALESCE(scope->>'Repository', 'Global')
               ORDER BY created_at ASC, policy_id ASC
           ) AS rn
    FROM public.policy_projections
    WHERE archived = false
)
UPDATE public.policy_projections pp
SET archived = true,
    updated_at = now()
FROM ranked
WHERE pp.policy_id = ranked.policy_id
  AND ranked.rn > 1;

CREATE UNIQUE INDEX idx_policy_projections_active_scope
    ON public.policy_projections USING btree (
        (COALESCE(scope->>'Repository', 'Global'))
    )
    WHERE (archived = false);
