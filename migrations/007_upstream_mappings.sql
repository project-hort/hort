-- Squashed baseline — repository upstream mappings.
--
-- One row maps a repository (and optional path prefix) to an upstream
-- registry. Pull-through proxies use this to find which upstream to
-- fetch from. The secret_ref / mTLS columns let an operator declare
-- credentials by reference (env var, file) without inlining secrets in
-- the database.

CREATE TABLE public.repository_upstream_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    repository_id uuid NOT NULL,
    -- Empty string = "applies to every path under this repo"; a
    -- specific value scopes the mapping to a sub-prefix.
    path_prefix text DEFAULT ''::text NOT NULL,
    upstream_url text NOT NULL,
    -- Optional outbound OCI path segment(s) spliced between `/v2/` and
    -- `<name>` (e.g. `docker.io` for a Zot multi-storage path). NULL =
    -- today's behaviour (no prefix). Validation regex mirrors the domain
    -- constructor in
    -- `crates/hort-domain/src/ports/repository_upstream_mapping_repository.rs`.
    upstream_name_prefix text,
    upstream_auth_type text NOT NULL,
    -- {source: env_var|file, location: <path-or-name>} — see chk below.
    secret_ref jsonb,
    managed_by text DEFAULT 'local'::text NOT NULL,
    managed_by_digest bytea,
    insecure_upstream_url boolean DEFAULT false NOT NULL,
    -- Per-upstream opt-in to publish-time-anchored quarantine (ADR 0007).
    -- When `true`, ingests through this mapping resolve their
    -- quarantine_window_start from `upstream_published_at` (clamped to
    -- `ingested_at`); when `false` (default), the anchor is `ingested_at`.
    -- Mirrors `insecure_upstream_url`'s per-mapping shape.
    trust_upstream_publish_time boolean DEFAULT false NOT NULL,
    -- mTLS material — cert and key are paired (both set or both NULL).
    mtls_cert_ref jsonb,
    mtls_key_ref jsonb,
    -- Custom CA bundle (for self-signed upstreams) and/or pinned cert.
    ca_bundle_ref jsonb,
    pinned_cert_sha256 text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    -- gitops/local managed-by digest enforcement.
    CONSTRAINT chk_repository_upstream_mappings_managed_digest CHECK (
        (((managed_by = 'gitops'::text) AND (managed_by_digest IS NOT NULL))
         OR ((managed_by = 'local'::text) AND (managed_by_digest IS NULL)))
    ),
    CONSTRAINT repository_upstream_mappings_managed_by_check CHECK (
        (managed_by = ANY (ARRAY['local'::text, 'gitops'::text]))
    ),
    -- mTLS cert and key are always declared as a pair.
    CONSTRAINT chk_repository_upstream_mappings_mtls_pair CHECK (
        ((mtls_cert_ref IS NULL) = (mtls_key_ref IS NULL))
    ),
    -- Pinned cert: 64 hex chars (SHA-256), or NULL.
    CONSTRAINT chk_repository_upstream_mappings_pin_hex CHECK (
        ((pinned_cert_sha256 IS NULL)
         OR ((length(pinned_cert_sha256) = 64) AND (pinned_cert_sha256 ~ '^[0-9a-f]+$'::text)))
    ),
    -- Outbound OCI path-prefix injection. Three guards working together
    -- mirror the domain constructor at
    -- crates/hort-domain/src/ports/repository_upstream_mapping_repository.rs
    -- (validate_upstream_name_prefix):
    --   1. anchored char-class regex pins the allowed alphabet
    --   2. `\.\.`-substring reject catches embedded `foo..bar`
    --   3. segment-of-dots reject catches standalone `.`/`..` segments
    CONSTRAINT chk_repository_upstream_mappings_name_prefix CHECK (
        upstream_name_prefix IS NULL
        OR (
            upstream_name_prefix ~ '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$'
            AND upstream_name_prefix !~ '\.\.'
            AND upstream_name_prefix !~ '(^|/)\.+($|/)'
        )
    ),
    -- Each *_ref jsonb has the same shape: {source: env_var|file, location: <string>}.
    CONSTRAINT repository_upstream_mappings_secret_ref_check CHECK (
        ((secret_ref IS NULL)
         OR ((secret_ref ? 'source'::text) AND (secret_ref ? 'location'::text)
             AND (jsonb_typeof((secret_ref -> 'source'::text)) = 'string'::text)
             AND (jsonb_typeof((secret_ref -> 'location'::text)) = 'string'::text)
             AND ((secret_ref ->> 'source'::text) = ANY (ARRAY['env_var'::text, 'file'::text]))))
    ),
    CONSTRAINT repository_upstream_mappings_mtls_cert_ref_check CHECK (
        ((mtls_cert_ref IS NULL)
         OR ((mtls_cert_ref ? 'source'::text) AND (mtls_cert_ref ? 'location'::text)
             AND (jsonb_typeof((mtls_cert_ref -> 'source'::text)) = 'string'::text)
             AND (jsonb_typeof((mtls_cert_ref -> 'location'::text)) = 'string'::text)
             AND ((mtls_cert_ref ->> 'source'::text) = ANY (ARRAY['env_var'::text, 'file'::text]))))
    ),
    CONSTRAINT repository_upstream_mappings_mtls_key_ref_check CHECK (
        ((mtls_key_ref IS NULL)
         OR ((mtls_key_ref ? 'source'::text) AND (mtls_key_ref ? 'location'::text)
             AND (jsonb_typeof((mtls_key_ref -> 'source'::text)) = 'string'::text)
             AND (jsonb_typeof((mtls_key_ref -> 'location'::text)) = 'string'::text)
             AND ((mtls_key_ref ->> 'source'::text) = ANY (ARRAY['env_var'::text, 'file'::text]))))
    ),
    CONSTRAINT repository_upstream_mappings_ca_bundle_ref_check CHECK (
        ((ca_bundle_ref IS NULL)
         OR ((ca_bundle_ref ? 'source'::text) AND (ca_bundle_ref ? 'location'::text)
             AND (jsonb_typeof((ca_bundle_ref -> 'source'::text)) = 'string'::text)
             AND (jsonb_typeof((ca_bundle_ref -> 'location'::text)) = 'string'::text)
             AND ((ca_bundle_ref ->> 'source'::text) = ANY (ARRAY['env_var'::text, 'file'::text]))))
    )
);

ALTER TABLE ONLY public.repository_upstream_mappings
    ADD CONSTRAINT repository_upstream_mappings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.repository_upstream_mappings
    ADD CONSTRAINT repository_upstream_mappings_repository_id_path_prefix_key
    UNIQUE (repository_id, path_prefix);

ALTER TABLE ONLY public.repository_upstream_mappings
    ADD CONSTRAINT repository_upstream_mappings_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES public.repositories(id) ON DELETE CASCADE;

CREATE INDEX idx_repository_upstream_mappings_repo
    ON public.repository_upstream_mappings USING btree (repository_id);

CREATE INDEX idx_repository_upstream_mappings_managed_by
    ON public.repository_upstream_mappings USING btree (managed_by)
    WHERE (managed_by = 'gitops'::text);
