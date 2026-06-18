-- Native API tokens (ADR 0012).
--
-- Adds the api_tokens table. This is a fresh CREATE with the v2-correct
-- shape: typed scopes (declared_permissions), Argon2id-encoded
-- token_hash, kind enum (pat/service_account/cli_session), and a 1 KB
-- description CHECK per GDPR data-minimisation review.
--
-- Schema choice: declared_permissions uses `text[]` (matches the v2
-- baseline's existing pattern in `roles.permissions text[]` from
-- 001_users_roles_rbac.sql). The `permission_type` enum from migration
-- 001 is used per-row by `permission_grants`, but every "bag of
-- permissions" column in the v2 baseline is `text[]`. Mirroring that
-- convention keeps the schema consistent and lets the adapter layer parse
-- strings into `hort_domain::Permission` with the same TryFrom<&str>
-- codepath the role repo already uses.
--
-- Reversal: the project uses sqlx::migrate! in UP-only mode (no
-- paired *.down.sql files exist anywhere in backend/migrations/ or
-- the prototype history). Manual reversal command, if ever needed
-- (operator runs against the DB directly):
--
--   DROP TABLE IF EXISTS public.api_tokens CASCADE;
--   -- The CASCADE-dropped table also takes its three indexes:
--   --   idx_api_tokens_prefix, idx_api_tokens_user, idx_api_tokens_revoked
--
-- Pre-v1.0 (per `feedback_pre_release_migrations`): if the schema
-- needs adjusting before GA, edit THIS file in place rather than
-- appending 009_api_tokens_alter_*.sql on top.
--
-- Idempotence: this migration runs exactly once via the _sqlx_migrations
-- bookkeeping table. CREATE TABLE deliberately has NO `IF NOT EXISTS`
-- guard — if a half-migrated database somehow already carries an
-- `api_tokens` table from the prototype era, the migration must fail
-- fast with `relation "api_tokens" already exists` so the operator
-- notices and drops the stale prototype table first. IF NOT EXISTS would
-- mask that case.

CREATE TABLE public.api_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    name character varying(255) NOT NULL,
    description text,
    -- 1 KB cap on description: longer values are wasteful and a small DoS
    -- vector on list_for_user. The use case maps the constraint to
    -- 400 invalid_description; raw INSERT bypassing the use case still
    -- gets caught at the schema layer (GDPR data-minimisation review).
    CONSTRAINT api_tokens_description_length_check CHECK (
        description IS NULL OR length(description) <= 1024
    ),
    kind character varying(32) NOT NULL DEFAULT 'pat'
        CHECK (kind IN ('pat', 'service_account', 'cli_session')),
    token_hash character varying(255) NOT NULL,           -- Argon2id encoded
    token_prefix character(8) NOT NULL,                   -- first 8 base32 chars of body
    declared_permissions text[] NOT NULL,                 -- subset of {read,write,delete,admin}
    repository_ids uuid[],                                -- NULL = inherit user grants
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    last_used_ip text,
    last_used_user_agent text,
    created_by_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_tokens_prefix ON public.api_tokens (token_prefix);
CREATE INDEX idx_api_tokens_user ON public.api_tokens (user_id);
CREATE INDEX idx_api_tokens_revoked ON public.api_tokens (revoked_at)
    WHERE revoked_at IS NOT NULL;
