-- Squashed baseline — users / RBAC. Rewritten to the additive-claims
-- model (ADR 0012): roles + group_mappings dropped. Password / TOTP /
-- lockout columns dropped end-to-end (no inbound consumer remained after
-- `admin bootstrap` CLI deletion and `authenticate_local` + lockout
-- machinery deletion).
--
-- Replaces the cumulative ALTER history from prototype migrations
-- 001, 002, 015–019, 026–034 (totp + lockout + service accounts +
-- gitops-managed flag), 040 (password expiry), 050 (role rename),
-- 094 (group mappings). Final shape captured in
-- tools/migration-baseline/baseline-cumulative.sql. Edits applied in
-- place per the pre-v1.0 migration discipline (ADR 0022, no ALTER-on-top):
-- dev environments running a prior `001` must drop the `roles`,
-- `group_mappings`, `permission_grants` tables and re-migrate.
--
-- Tables:
--   users               — local + external (LDAP / SAML / OIDC) accounts.
--                          Identity-only — no password / TOTP / lockout
--                          columns; the inbound auth path is OIDC + native
--                          tokens.
--   claim_mappings      — external-IdP `groups`-claim string → registry
--                          claim name (ADR 0012 — replaces group_mappings).
--                          The only source of resolved claim names.
--   permission_grants   — (subject, optional repository, permission) rows.
--                          subject = Claims(required_claims[]) XOR
--                          User(user_id) (ADR 0012). repository_id NULL
--                          means "global". gitops managed-by digest
--                          enforced by chk_*.
--
-- The `roles` table and the role->permission bundle are removed (ADR 0012):
-- permission bundling lives in operator-side YAML templating, not the data
-- layer. `permission_grants.role_id` is replaced by the sum-typed subject
-- columns.

-- ---------------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------------

CREATE TYPE public.auth_provider AS ENUM (
    'local',
    'ldap',
    'saml',
    'oidc'
);

CREATE TYPE public.permission_type AS ENUM (
    'read',
    'write',
    'delete',
    'admin',
    'admin_task_invoke',   -- admin-task invocation permission
    'curate',              -- curation-rule management permission
    'prefetch'             -- self-service prefetch permission
);

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    username character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    auth_provider public.auth_provider DEFAULT 'local'::public.auth_provider NOT NULL,
    external_id character varying(512),
    display_name character varying(255),
    is_active boolean DEFAULT true NOT NULL,
    is_admin boolean DEFAULT false NOT NULL,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_service_account boolean DEFAULT false NOT NULL
);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);

CREATE INDEX idx_users_username ON public.users USING btree (username);

CREATE UNIQUE INDEX idx_users_auth_provider_external_id
    ON public.users USING btree (auth_provider, external_id);

CREATE INDEX idx_users_service_account ON public.users USING btree (is_service_account)
    WHERE (is_service_account = true);

-- ---------------------------------------------------------------------------
-- claim_mappings  (ADR 0012 — replaces the dropped group_mappings)
--
-- Declarative mapping from an IdP `groups`-claim string to a registry
-- claim name. The OIDC / CLI-session auth paths flatten the caller's
-- `groups` claim against this table to produce `principal.claims`
-- (`crates/hort-app/src/use_cases/rbac.rs`). This is the ONLY source of
-- resolved claim names (ADR 0012 invariant 6). PATs do NOT consult this
-- table — long-lived static tokens stay under-privileged.
--
-- The `roles` table, the `group_mappings` table, the role->permission
-- bundle, and `permission_grants.role_id` are deleted by this migration:
-- RBAC collapses into additive claims (ADR 0012). Permission bundling
-- moves to operator-side YAML templating. The bootstrap admin USER is
-- provisioned programmatically at first boot (`provision_admin_user` in
-- the binary) and gets the synthetic `admin` claim from
-- `users.is_admin=true`, so no role seed rows are needed.
-- ---------------------------------------------------------------------------

CREATE TABLE public.claim_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    idp_group character varying(255) NOT NULL,
    claim character varying(255) NOT NULL,
    managed_by text DEFAULT 'local'::text NOT NULL,
    managed_by_digest bytea,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_claim_mappings_managed_digest CHECK (
        (((managed_by = 'gitops'::text) AND (managed_by_digest IS NOT NULL))
         OR ((managed_by = 'local'::text) AND (managed_by_digest IS NULL)))
    ),
    CONSTRAINT claim_mappings_managed_by_check CHECK (
        (managed_by = ANY (ARRAY['local'::text, 'gitops'::text]))
    )
);

ALTER TABLE ONLY public.claim_mappings
    ADD CONSTRAINT claim_mappings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.claim_mappings
    ADD CONSTRAINT claim_mappings_idp_group_claim_key UNIQUE (idp_group, claim);

CREATE INDEX idx_claim_mappings_idp_group
    ON public.claim_mappings USING btree (idp_group);

-- ---------------------------------------------------------------------------
-- permission_grants  (ADR 0012 — rewritten to a sum-typed subject)
--
-- A grant binds to EITHER a set of required claims (`required_claims`,
-- subject = Claims) OR a single user id (`user_id`, subject = User) —
-- never both, never neither (the `subject_exclusive` CHECK). The
-- `claims_nonempty` CHECK forbids `required_claims = '{}'` (an empty set
-- means "no claim requirements" — an unintended wildcard; the apply-time
-- linter also catches it, the DB is the backstop).
--
-- repository_id NULL means "global" — the permission applies to every
-- repository. The FK to repositories is added in 002_repositories.sql
-- (`fk_permission_grants_repository`, on the still-present
-- `repository_id` column) because repositories doesn't exist yet here.
-- The `user_id` FK is inline — `users` is created above in this file.
-- ---------------------------------------------------------------------------

CREATE TABLE public.permission_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    required_claims text[],
    user_id uuid,
    permission public.permission_type NOT NULL,
    repository_id uuid,
    managed_by text DEFAULT 'local'::text NOT NULL,
    managed_by_digest bytea,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT subject_exclusive CHECK (
        ((required_claims IS NOT NULL) AND (user_id IS NULL))
         OR ((required_claims IS NULL) AND (user_id IS NOT NULL))
    ),
    CONSTRAINT claims_nonempty CHECK (
        (required_claims IS NULL) OR (cardinality(required_claims) >= 1)
    ),
    CONSTRAINT chk_permission_grants_managed_digest CHECK (
        (((managed_by = 'gitops'::text) AND (managed_by_digest IS NOT NULL))
         OR ((managed_by = 'local'::text) AND (managed_by_digest IS NULL)))
    ),
    CONSTRAINT permission_grants_managed_by_check CHECK (
        (managed_by = ANY (ARRAY['local'::text, 'gitops'::text]))
    )
);

ALTER TABLE ONLY public.permission_grants
    ADD CONSTRAINT permission_grants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.permission_grants
    ADD CONSTRAINT permission_grants_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

CREATE INDEX idx_grants_repo
    ON public.permission_grants USING btree (repository_id);

CREATE INDEX idx_grants_user
    ON public.permission_grants USING btree (user_id)
    WHERE (user_id IS NOT NULL);

CREATE INDEX idx_grants_claims_gin
    ON public.permission_grants USING gin (required_claims)
    WHERE (required_claims IS NOT NULL);

-- Retained for the gitops apply diff (managed-by partial scan).
CREATE INDEX idx_permission_grants_managed_by
    ON public.permission_grants USING btree (managed_by)
    WHERE (managed_by = 'gitops'::text);
