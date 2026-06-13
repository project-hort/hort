-- Squashed baseline — artifacts and CAS-adjacent tables.
--
-- Replaces the cumulative ALTER history from prototype migrations
-- 004 (initial), 010 (path UNIQUE), 022 (quarantine columns),
-- 067 (name_as_published), 086 (mutable_refs), 087 (artifact_groups
-- + artifact_group_members), 090 (content_references for SBOM/promote
-- transparency), and intervening tweaks.
--
-- Tables:
--   artifacts              — primary artifact catalog. One row per
--                             content-addressable blob in the registry.
--                             Quarantine columns gate downloads
--                             (status='quarantined' blocks even when the
--                             observation window has elapsed; the
--                             background sweep is what releases — not a
--                             clean scan). The stored column is the
--                             immutable window *anchor*
--                             (quarantine_window_start, ADR 0007),
--                             never a precomputed deadline; the deadline
--                             is derived live as anchor + duration.
--   artifact_groups        — multi-file logical bundles (Maven POM+JAR,
--                             Go module zip+mod+info, etc.). The
--                             coords_json keys the bundle.
--   artifact_group_members — group↔artifact junction with `role` denoting
--                             the file's purpose within the group
--                             (e.g. 'pom', 'jar', 'sources', 'javadoc').
--   content_references     — SBOM + promote transparency: which artifacts
--                             reference which other content hashes. Used
--                             to answer "what depends on this CVE'd
--                             artifact?" without scanning every blob.
--   artifact_metadata      — typed format-specific metadata sidecar.
--                             1-MB cap enforced via CHECK so a malformed
--                             upload can't bloat the catalog.
--   mutable_refs           — registry-format mutable pointers (Docker tags,
--                             Helm chart latest, etc.). EXACTLY ONE of
--                             target_hash / target_version is non-NULL,
--                             enforced via chk_target_exactly_one.
--
-- Notable absences carried from the prototype dump (deliberate drops):
--   - idx_artifacts_name_gin — depended on pg_trgm. Zero v2 queries used
--     trigram operators; the index plus the extension are dropped.
--     See design §2.3 and tools/migration-baseline/README.md.

-- ---------------------------------------------------------------------------
-- artifacts
-- ---------------------------------------------------------------------------

CREATE TABLE public.artifacts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    repository_id uuid NOT NULL,
    path character varying(2048) NOT NULL,
    name character varying(512) NOT NULL,
    version character varying(255),
    size_bytes bigint NOT NULL,
    checksum_sha256 character(64) NOT NULL,
    checksum_md5 character(32),
    checksum_sha1 character(40),
    content_type character varying(255) NOT NULL,
    storage_key character varying(2048) NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    uploaded_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    quarantine_status character varying(20),
    -- The immutable observation-window *anchor*, not a precomputed
    -- deadline (ADR 0007). Resolves to `ingested_at` by default (or
    -- `min(upstream_published_at, ingested_at)` under the per-upstream
    -- publish-anchoring opt-in). The window deadline is a derived value
    -- (`anchor + duration`, the duration resolved from the matched
    -- ScanPolicy) computed live by the release sweep, the scan fast path,
    -- and the proxy-503 Retry-After read path — never stored, so an
    -- operator changing `quarantineDuration` is honoured by in-flight
    -- quarantines without a bulk UPDATE.
    quarantine_window_start timestamp with time zone,
    -- Upstream-asserted publish timestamp (ADR 0007),
    -- recorded best-effort at ingest from per-format upstream metadata
    -- (npm packument `time[<version>]`, PyPI `upload_time_iso_8601`,
    -- Cargo / OCI `Last-Modified` header). Nullable, no default:
    -- absent = "no upstream-published-at known" (direct upload, an
    -- upstream that did not supply a parseable value). **Audit field —
    -- untrusted upstream-asserted input.** Recording it is not
    -- trusting it; the window-anchor computation that consumes it
    -- (Phase 2 / Item 6) is gated separately on the per-upstream
    -- `RepositoryUpstreamMapping.trust_upstream_publish_time` opt-in.
    upstream_published_at timestamp with time zone,
    name_as_published text NOT NULL,
    -- Use the IN (...) form so Postgres normalises this CHECK to
    -- the same internal shape the prototype's 075_quarantine_period.sql
    -- produced (per-element casts). The array-cast form parses but
    -- normalises differently, breaking schema-parity.
    -- 'scan_indeterminate' — terminal scan failure (ADR 0007): the
    -- scan job exhausted retries with every backend errored. Fail-closed
    -- non-downloadable state distinct from 'rejected' (no finding). Added
    -- to the IN-list per the pre-v1.0 "edit the original migration"
    -- convention rather than an appended ALTER.
    CONSTRAINT artifacts_quarantine_status_check CHECK (
        quarantine_status IN ('unscanned', 'clean', 'flagged', 'quarantined', 'released', 'rejected', 'scan_indeterminate')
    )
);

ALTER TABLE ONLY public.artifacts
    ADD CONSTRAINT artifacts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.artifacts
    ADD CONSTRAINT artifacts_repository_id_path_key UNIQUE (repository_id, path);

ALTER TABLE ONLY public.artifacts
    ADD CONSTRAINT artifacts_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES public.repositories(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.artifacts
    ADD CONSTRAINT artifacts_uploaded_by_fkey
    FOREIGN KEY (uploaded_by) REFERENCES public.users(id) ON DELETE SET NULL;

CREATE INDEX idx_artifacts_checksum
    ON public.artifacts USING btree (checksum_sha256);

CREATE INDEX idx_artifacts_name_as_published
    ON public.artifacts USING btree (repository_id, name_as_published)
    WHERE (is_deleted = false);

CREATE INDEX idx_artifacts_quarantine
    ON public.artifacts USING btree (quarantine_status)
    WHERE (quarantine_status IS NOT NULL);

-- Background sweep query: "which artifacts have hit their quarantine
-- expiry and need releasing?" The sweep computes the deadline live
-- (anchor + duration, ADR 0007) and issues one indexed range scan
-- per distinct duration over `quarantine_window_start`. Partial index
-- keeps the scan cheap.
CREATE INDEX idx_artifacts_quarantine_window_start
    ON public.artifacts USING btree (quarantine_window_start)
    WHERE (((quarantine_status)::text = 'quarantined'::text) AND (quarantine_window_start IS NOT NULL));

CREATE INDEX idx_artifacts_repo_name_version
    ON public.artifacts USING btree (repository_id, name, version);

CREATE INDEX idx_artifacts_repo_path
    ON public.artifacts USING btree (repository_id, path);

-- Covering index for the per-(package, version) servability query
-- (`ArtifactRepository::package_version_status`), the hot read path of
-- the quarantine-aware index-serve filter. An npm/PyPI/Cargo/Maven index
-- resolution fires this query dozens to hundreds of times per `install`;
-- the served-document filter cannot afford a heap fetch per match.
-- `(repository_id, name)` is the lookup key; `INCLUDE (version,
-- quarantine_status)` keeps the row payload in the leaf so Postgres plans
-- an index-only scan with no heap visit. `WHERE NOT is_deleted` matches
-- the query predicate exactly — a partial index that excludes the (in
-- steady state, large) soft-deleted tail. This is the highest-QPS new
-- query and the single most important optimisation in the servability path.
CREATE INDEX idx_artifacts_repo_name_status_covering
    ON public.artifacts USING btree (repository_id, name)
    INCLUDE (version, quarantine_status)
    WHERE (is_deleted = false);

-- ---------------------------------------------------------------------------
-- artifact_groups
-- ---------------------------------------------------------------------------

CREATE TABLE public.artifact_groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    repository_id uuid NOT NULL,
    coords_json jsonb NOT NULL,
    primary_role text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.artifact_groups
    ADD CONSTRAINT artifact_groups_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.artifact_groups
    ADD CONSTRAINT artifact_groups_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES public.repositories(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX idx_artifact_groups_repo_coords
    ON public.artifact_groups USING btree (repository_id, coords_json);

-- Lookup-by-name for format handlers that index by package name.
CREATE INDEX idx_artifact_groups_repo_role_name
    ON public.artifact_groups USING btree (
        repository_id, primary_role, ((coords_json ->> 'name'::text)) COLLATE "C"
    );

-- ---------------------------------------------------------------------------
-- artifact_group_members
-- ---------------------------------------------------------------------------

CREATE TABLE public.artifact_group_members (
    group_id uuid NOT NULL,
    role text NOT NULL,
    artifact_id uuid NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.artifact_group_members
    ADD CONSTRAINT artifact_group_members_pkey PRIMARY KEY (group_id, artifact_id);

ALTER TABLE ONLY public.artifact_group_members
    ADD CONSTRAINT artifact_group_members_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES public.artifact_groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.artifact_group_members
    ADD CONSTRAINT artifact_group_members_artifact_id_fkey
    FOREIGN KEY (artifact_id) REFERENCES public.artifacts(id) ON DELETE CASCADE;

CREATE INDEX idx_artifact_group_members_artifact
    ON public.artifact_group_members USING btree (artifact_id);

-- ---------------------------------------------------------------------------
-- content_references
-- ---------------------------------------------------------------------------

CREATE TABLE public.content_references (
    source_artifact_id uuid NOT NULL,
    target_content_hash text NOT NULL,
    kind text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    repository_id uuid NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.content_references
    ADD CONSTRAINT content_references_pkey PRIMARY KEY (repository_id, source_artifact_id, kind);

ALTER TABLE ONLY public.content_references
    ADD CONSTRAINT content_references_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES public.repositories(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.content_references
    ADD CONSTRAINT content_references_source_artifact_id_fkey
    FOREIGN KEY (source_artifact_id) REFERENCES public.artifacts(id) ON DELETE CASCADE;

CREATE INDEX idx_content_references_source
    ON public.content_references USING btree (source_artifact_id);

CREATE INDEX idx_content_references_target
    ON public.content_references USING btree (repository_id, target_content_hash);

CREATE INDEX idx_content_references_target_kind
    ON public.content_references USING btree (repository_id, target_content_hash, kind);

-- Back-fill primary_content refcount rows for every existing artifact,
-- so the projection is authoritative from the moment it ships.
-- Metadata-blob back-fill rides on the same metadata-blob migration
-- (cross-referenced — not duplicated here).
INSERT INTO public.content_references
    (source_artifact_id, target_content_hash, kind, metadata, repository_id, recorded_at)
SELECT a.id, a.checksum_sha256, 'primary_content', '{}'::jsonb, a.repository_id, a.created_at
FROM public.artifacts a
ON CONFLICT (repository_id, source_artifact_id, kind) DO NOTHING;

-- ---------------------------------------------------------------------------
-- artifact_metadata
-- ---------------------------------------------------------------------------

CREATE TABLE public.artifact_metadata (
    artifact_id uuid NOT NULL,
    format text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    metadata_blob character(64),
    -- 1 MB hard cap on the metadata blob — defense against a runaway
    -- format handler bloating the catalog. Realistic envelopes are sub-KB.
    CONSTRAINT artifact_metadata_metadata_check CHECK (
        (octet_length((metadata)::text) <= 1048576)
    )
);

ALTER TABLE ONLY public.artifact_metadata
    ADD CONSTRAINT artifact_metadata_pkey PRIMARY KEY (artifact_id);

ALTER TABLE ONLY public.artifact_metadata
    ADD CONSTRAINT artifact_metadata_artifact_id_fkey
    FOREIGN KEY (artifact_id) REFERENCES public.artifacts(id) ON DELETE CASCADE;

CREATE INDEX idx_artifact_metadata_gin
    ON public.artifact_metadata USING gin (metadata);

-- ---------------------------------------------------------------------------
-- mutable_refs
-- ---------------------------------------------------------------------------

CREATE TABLE public.mutable_refs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    repository_id uuid NOT NULL,
    namespace text NOT NULL,
    ref_name text NOT NULL,
    target_kind text NOT NULL,
    target_hash character(64),
    target_version text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    -- Either target_hash (immutable content pointer) OR target_version
    -- (mutable version pointer), never both, never neither.
    CONSTRAINT chk_target_exactly_one CHECK (
        (target_kind = ANY (ARRAY['hash'::text, 'version'::text]))
        AND (((target_kind = 'hash'::text) AND (target_hash IS NOT NULL) AND (target_version IS NULL))
             OR ((target_kind = 'version'::text) AND (target_version IS NOT NULL) AND (target_hash IS NULL)))
    )
);

ALTER TABLE ONLY public.mutable_refs
    ADD CONSTRAINT mutable_refs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.mutable_refs
    ADD CONSTRAINT mutable_refs_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES public.repositories(id) ON DELETE CASCADE;

CREATE INDEX idx_mutable_refs_repo_namespace
    ON public.mutable_refs USING btree (repository_id, namespace);

CREATE UNIQUE INDEX idx_mutable_refs_repo_namespace_ref
    ON public.mutable_refs USING btree (repository_id, namespace, ref_name);

CREATE INDEX idx_mutable_refs_target_hash
    ON public.mutable_refs USING btree (repository_id, target_hash)
    WHERE (target_hash IS NOT NULL);

CREATE INDEX idx_mutable_refs_target_version
    ON public.mutable_refs USING btree (repository_id, target_version)
    WHERE (target_version IS NOT NULL);
