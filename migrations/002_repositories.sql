-- Squashed baseline — repositories.
--
-- Replaces the cumulative ALTER history from prototype migrations
-- 003 (initial), 008–009 (storage backend / quota), 011 (replication
-- priority), 020 (promotion target/policy), 050–055 (managed_by /
-- gitops), 091 (format_key), 092 (repo_type rename), 093 (managed_by),
-- 096 (index_upstream_url for Cargo split-host metadata).
--
-- Tables:
--   repositories         — every hosted, proxy, virtual, or staging repo.
--                          One row per logical registry endpoint.
--   virtual_repo_members — membership of a virtual repository (virtual
--                          repos federate over an ordered list of members).
--
-- Cross-file: this file also adds the deferred FK from
-- permission_grants(repository_id) -> repositories(id), which could
-- not be declared in 001 because repositories did not exist yet.

-- ---------------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------------

CREATE TYPE public.repository_type AS ENUM (
    'hosted',
    'proxy',
    'virtual',
    'staging'
);

-- The full prototype enum carried 53 format names; v2 keeps the canonical
-- list because dropping values from a Postgres enum requires recreating
-- the type and rewriting every column. Format dispatch in v2 is keyed on
-- `format_key` (TEXT, columns added below) — the typed `format` column
-- exists for backwards-compatible read paths and operator-facing
-- inspection.
CREATE TYPE public.repository_format AS ENUM (
    'maven',
    'gradle',
    'npm',
    'pypi',
    'nuget',
    'go',
    'rubygems',
    'docker',
    'helm',
    'rpm',
    'debian',
    'conan',
    'cargo',
    'generic',
    'podman',
    'buildx',
    'oras',
    'wasm_oci',
    'helm_oci',
    'poetry',
    'conda',
    'yarn',
    'bower',
    'pnpm',
    'chocolatey',
    'powershell',
    'terraform',
    'opentofu',
    'alpine',
    'conda_native',
    'composer',
    'hex',
    'cocoapods',
    'swift',
    'pub',
    'sbt',
    'chef',
    'puppet',
    'ansible',
    'gitlfs',
    'vscode',
    'jetbrains',
    'huggingface',
    'mlmodel',
    'cran',
    'vagrant',
    'opkg',
    'p2',
    'bazel',
    'protobuf',
    'incus',
    'lxc',
    'oci'
);

CREATE TYPE public.replication_priority AS ENUM (
    'immediate',
    'scheduled',
    'on_demand',
    'local_only'
);

-- ---------------------------------------------------------------------------
-- repositories
-- ---------------------------------------------------------------------------

CREATE TABLE public.repositories (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    format public.repository_format NOT NULL,
    repo_type public.repository_type NOT NULL,
    storage_backend character varying(50) DEFAULT 'filesystem'::character varying NOT NULL,
    storage_path character varying(1024) NOT NULL,
    upstream_url character varying(2048),
    is_public boolean DEFAULT false NOT NULL,
    -- Opt-in per-repository download auditing (ADR 0020). When true, every
    -- served download appends one ArtifactDownloaded event to a dedicated
    -- per-(repo, UTC-date) DownloadAudit stream (fail-open). CRUD, not
    -- event-sourced. Pre-release in-place column add (mirrors the
    -- is_public precedent).
    download_audit_enabled boolean DEFAULT false NOT NULL,
    -- Quarantine-aware index-serve mode (ADR 0007). Controls how the served
    -- package/index/metadata document is filtered against the registry's
    -- per-(package, version) quarantine status. Default `released_only` is
    -- build-safe by construction (a range never 503s); `include_pending` is
    -- the maximal-discoverability posture (renamed from `filter_quarantined`
    -- pre-v1.0 in-place; the posture-ordered pair reads strict → permissive).
    -- Pre-release in-place column add (mirrors the download_audit_enabled
    -- precedent).
    index_mode text DEFAULT 'released_only' NOT NULL,
    -- Per-repository prefetch policy — proactive background ingestion so
    -- the quarantine window elapses off the build's critical path. CRUD
    -- config; triggers and the transitive cascade are the consumers.
    --
    -- `prefetch_enabled` is the master switch — default `false` so an
    -- upgrade of the v2 binary cannot silently turn a repository into
    -- a mirror (mirrors the `download_audit_enabled` precedent).
    --
    -- `prefetch_triggers` is a `text[]` of snake_case literals
    -- matching `PrefetchTrigger`'s `Display` strings. **Empty-list
    -- representation:** the column is nullable, and `NULL` is the
    -- canonical "no triggers" encoding — the mapper treats both
    -- `NULL` and `'{}'` as an empty `Vec<PrefetchTrigger>`. The CHECK
    -- below validates each element when the array is non-NULL
    -- (`NULL` skips CHECK by SQL semantics, so an absent triggers
    -- list cannot violate the constraint).
    --
    -- `prefetch_depth` / `prefetch_transitive_depth` / `prefetch_max_age_days`
    -- / `prefetch_max_descendants` are nullable knobs: `NULL` means
    -- "use the in-code default" so existing rows round-trip without
    -- surfacing operator-irrelevant numbers. Pre-release in-place
    -- column add (no ALTER on top).
    --
    -- `prefetch_max_descendants` is the global cumulative cap on the
    -- transitive cascade — bounds breadth where `prefetch_transitive_depth`
    -- only bounds depth. The default (200) lives in
    -- `PrefetchPolicy::default()`; the row mapper reads `NULL` → in-code
    -- default. NOT `NOT NULL DEFAULT 200` — that diverges from the
    -- established nullable-knob convention without an objectively-better
    -- case.
    prefetch_enabled boolean DEFAULT false NOT NULL,
    prefetch_triggers text[],
    prefetch_depth int,
    prefetch_transitive_depth int,
    prefetch_max_age_days int,
    prefetch_max_descendants int,
    quota_bytes bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    replication_priority public.replication_priority DEFAULT 'on_demand'::public.replication_priority NOT NULL,
    promotion_target_id uuid,
    promotion_policy_id uuid,
    require_approval boolean DEFAULT false,
    format_key text,
    managed_by text DEFAULT 'local'::text NOT NULL,
    managed_by_digest bytea,
    -- Cargo cross-host metadata override (ADR 0006). Optional;
    -- only consulted by the Cargo proxy metadata path. NULL on every
    -- non-Cargo proxy and on every Cargo hosted repo.
    index_upstream_url text,
    CONSTRAINT check_upstream_url CHECK (
        (((repo_type = 'proxy'::public.repository_type) AND (upstream_url IS NOT NULL))
         OR (repo_type <> 'proxy'::public.repository_type))
    ),
    CONSTRAINT chk_repositories_managed_digest CHECK (
        (((managed_by = 'gitops'::text) AND (managed_by_digest IS NOT NULL))
         OR ((managed_by = 'local'::text) AND (managed_by_digest IS NULL)))
    ),
    CONSTRAINT repositories_managed_by_check CHECK (
        (managed_by = ANY (ARRAY['local'::text, 'gitops'::text]))
    ),
    -- `index_mode` is restricted to the documented value-domain. Out-of-band
    -- literals are rejected at write time so the mapper's defensive
    -- `unwrap_or(IndexMode::ReleasedOnly)` is belt-and-braces only.
    CONSTRAINT repositories_index_mode_check CHECK (
        (index_mode = ANY (ARRAY['released_only'::text, 'include_pending'::text]))
    ),
    -- Every element of `prefetch_triggers` must be one of the three
    -- documented `PrefetchTrigger` literals (Display strings — pinned by
    -- `prefetch_trigger_display_strings_match_migration_check` in
    -- `crates/hort-domain`). The `'on_index_fetch'` literal was dropped
    -- pre-v1.0 (in-place removal — see CLAUDE.local.md); the data-fix
    -- UPDATE that idempotently strips
    -- it from existing rows is appended below the table DDL. NULL
    -- skips the CHECK (SQL semantics) — the canonical "no triggers"
    -- representation is NULL, not `'{}'`. The subset operator `<@`
    -- makes this an O(N) array test; the mapper's defensive
    -- `from_str().ok()` per element keeps an out-of-band literal
    -- from panicking belt-and-braces.
    CONSTRAINT repositories_prefetch_triggers_check CHECK (
        prefetch_triggers IS NULL
        OR prefetch_triggers <@ ARRAY[
            'transitive_deps'::text,
            'scheduled'::text,
            'on_dist_tag_move'::text
        ]
    )
);

-- Idempotent data-fix UPDATE that strips the removed `'on_index_fetch'`
-- element from any existing row's
-- `prefetch_triggers` array. Order matters: the CHECK constraint
-- above must be loosened FIRST (above), then this UPDATE runs without
-- tripping the still-strict constraint mid-transaction. The column is
-- `prefetch_triggers text[]` (separate column, NOT a JSONB envelope —
-- see the column declaration above), so `array_remove` is the right
-- primitive (not `jsonb_set` / `?` / `->`). The `WHERE` guard makes
-- the UPDATE no-op on freshly initialised installs where no stale
-- row exists.
UPDATE public.repositories
   SET prefetch_triggers = array_remove(prefetch_triggers, 'on_index_fetch')
 WHERE 'on_index_fetch' = ANY(prefetch_triggers);

ALTER TABLE ONLY public.repositories
    ADD CONSTRAINT repositories_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.repositories
    ADD CONSTRAINT repositories_key_key UNIQUE (key);

-- Self-reference: staging repos point at their promotion target.
ALTER TABLE ONLY public.repositories
    ADD CONSTRAINT repositories_promotion_target_id_fkey
    FOREIGN KEY (promotion_target_id) REFERENCES public.repositories(id);

CREATE INDEX idx_repositories_managed_by ON public.repositories USING btree (managed_by)
    WHERE (managed_by = 'gitops'::text);

CREATE INDEX idx_repositories_replication_priority
    ON public.repositories USING btree (replication_priority)
    WHERE (replication_priority <> 'local_only'::public.replication_priority);

-- ---------------------------------------------------------------------------
-- virtual_repo_members
--
-- Ordered membership of a virtual repository. `priority` is a
-- per-virtual-repo ordering used at resolution time; lower wins.
-- ---------------------------------------------------------------------------

CREATE TABLE public.virtual_repo_members (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    virtual_repo_id uuid NOT NULL,
    member_repo_id uuid NOT NULL,
    priority integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.virtual_repo_members
    ADD CONSTRAINT virtual_repo_members_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.virtual_repo_members
    ADD CONSTRAINT virtual_repo_members_virtual_repo_id_member_repo_id_key
    UNIQUE (virtual_repo_id, member_repo_id);

ALTER TABLE ONLY public.virtual_repo_members
    ADD CONSTRAINT virtual_repo_members_virtual_repo_id_fkey
    FOREIGN KEY (virtual_repo_id) REFERENCES public.repositories(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.virtual_repo_members
    ADD CONSTRAINT virtual_repo_members_member_repo_id_fkey
    FOREIGN KEY (member_repo_id) REFERENCES public.repositories(id) ON DELETE CASCADE;

-- ---------------------------------------------------------------------------
-- Deferred FK from 001
-- ---------------------------------------------------------------------------
-- permission_grants.repository_id -> repositories.id. Declared here
-- because repositories did not exist yet in 001_users_roles_rbac.sql.

ALTER TABLE ONLY public.permission_grants
    ADD CONSTRAINT fk_permission_grants_repository
    FOREIGN KEY (repository_id) REFERENCES public.repositories(id) ON DELETE CASCADE;
