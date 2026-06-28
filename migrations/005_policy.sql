-- Squashed baseline — policy projections.
--
-- Policy is event-sourced (ADR 0002); the two tables here are read-side
-- projections that the policy engine and the gitops reconciler query for
-- the current effective policy.
--
-- Tables:
--   policy_projections    — current policy state, one row per active or
--                            archived policy. Built by replaying the
--                            "policy" stream events
--                            (PolicyCreated / PolicyUpdated / PolicyArchived).
--   exclusion_projections — per-policy CVE / package-pattern exclusions
--                            (ExclusionAdded / ExclusionRemoved). Adding
--                            an exclusion may re-evaluate previously
--                            rejected artifacts.
--
-- Note: the prototype scan_policies CRUD table is dropped — v2 reads
-- policy via the projections above, not via the legacy CRUD table.
-- Confirmed via `grep -rn scan_policies crates/` returning empty.

-- ---------------------------------------------------------------------------
-- policy_projections
-- ---------------------------------------------------------------------------

CREATE TABLE public.policy_projections (
    policy_id uuid NOT NULL,
    name text NOT NULL,
    scope jsonb NOT NULL,
    severity_threshold text NOT NULL,
    -- Names of the scanner backends this policy invokes per scan, in
    -- declared order. Each entry must match a backend registered in
    -- `scanner_registry` (validated at gitops apply time). An empty array
    -- means "no scanning". Default `{trivy}` mirrors
    -- `DefaultPolicy::block_on_critical_default_backends` so policies
    -- created before scanBackends was wired through the YAML still scan
    -- with Trivy out of the box.
    scan_backends text[] DEFAULT ARRAY['trivy']::text[] NOT NULL,
    -- Interval in hours between bulk re-scans of artifacts governed by
    -- this policy. The cron-rescan-tick handler reads this column
    -- per-policy. The value `0` is explicitly meaningful: it disables
    -- rescanning for every artifact governed by this policy (the
    -- eligibility query filters `rescan_interval_hours > 0`). Apply-
    -- pipeline validation rejects negative values. Default 24 mirrors
    -- `DefaultPolicy::rescan_interval_hours`.
    rescan_interval_hours integer DEFAULT 24 NOT NULL,
    quarantine_duration_secs bigint NOT NULL,
    require_approval boolean NOT NULL,
    -- Per-policy supply-chain provenance enforcement. Supersedes the
    -- dormant inert `requireSignature` boolean column — the bool was
    -- parsed/applied/event-sourced but read by no release gate, so the
    -- pre-1.0 swap drops it in place (no data to preserve) per the
    -- "edit the original migration" rule (ADR 0022).
    --
    --   provenance_mode       — `off | verify_if_present | required`;
    --                           default `verify_if_present` (the fail-safe
    --                           default that never gates release).
    --   provenance_backends   — verifier names to run (mirrors
    --                           `scan_backends`); default `{cosign}`. An
    --                           empty array is permitted ONLY when
    --                           provenance_mode = 'off' (CHECK below).
    --   provenance_identities — JSONB array of `{issuer, san}` allowed
    --                           signer patterns; default `[]`. The
    --                           per-element constructor validator
    --                           (`SignerIdentityPattern::new`) is the
    --                           authoritative shape check; the JSONB CHECK
    --                           below mirrors only the structural
    --                           invariants (non-empty issuer + san, count
    --                           <= cap). The mode<->identity COMBINATION
    --                           rules (Required+empty=reject etc.) are the
    --                           apply-time linter's job, not a DB
    --                           constraint.
    provenance_mode text DEFAULT 'verify_if_present' NOT NULL,
    provenance_backends text[] DEFAULT ARRAY['cosign']::text[] NOT NULL,
    provenance_identities jsonb DEFAULT '[]'::jsonb NOT NULL,
    max_artifact_age_secs bigint,
    license_policy jsonb DEFAULT '{}'::jsonb NOT NULL,
    archived boolean DEFAULT false NOT NULL,
    -- Optimistic concurrency for the projection writer: the version of
    -- the source stream the projection currently reflects.
    stream_version bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    -- Operator knob steering how negligible / informational advisories
    -- (RustSec unmaintained / unsound / notice; carry no CVSS) affect the
    -- release decision:
    --   'ignore' (default) — never block (informational != vulnerable);
    --   'warn'             — record a PolicyEvaluated observation, do not block;
    --   'block'            — reject (refuse unmaintained / unsound dependencies).
    -- The scan evaluator reads this column through the policy projection.
    negligible_action text DEFAULT 'ignore' NOT NULL,
    CONSTRAINT policy_projections_severity_threshold_check CHECK (
        (severity_threshold = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text]))
    ),
    -- provenance_mode is one of the three wire values.
    CONSTRAINT policy_projections_provenance_mode_check CHECK (
        (provenance_mode = ANY (ARRAY['off'::text, 'verify_if_present'::text, 'required'::text]))
    ),
    -- An empty provenance_backends array is permitted
    -- ONLY when provenance is off (a non-off mode with no verifier is
    -- inert; rejected at apply time and as defence-in-depth here).
    CONSTRAINT policy_projections_provenance_backends_nonempty_unless_off CHECK (
        (provenance_mode = 'off'::text) OR (cardinality(provenance_backends) > 0)
    ),
    -- JSONB-shape CHECK on provenance_identities:
    -- it must be an array, with at most MAX_PROVENANCE_IDENTITIES (32)
    -- elements, each a non-empty `issuer` + `san` string (mirrors the
    -- domain SignerIdentityPattern::new structural invariants — the per-
    -- element validator is authoritative; this is defence-in-depth).
    -- Expressed subquery-free: Postgres forbids subqueries in CHECK
    -- constraints, so per-element validation is the count of well-formed
    -- elements (selected by the jsonpath filter) equalling the total
    -- element count. An empty array trivially satisfies it (0 = 0).
    CONSTRAINT policy_projections_provenance_identities_shape CHECK (
        jsonb_typeof(provenance_identities) = 'array'
        AND jsonb_array_length(provenance_identities) <= 32
        AND jsonb_array_length(provenance_identities) = jsonb_array_length(
            jsonb_path_query_array(
                provenance_identities,
                '$[*] ? (@.type() == "object" && @.issuer.type() == "string" && @.issuer != "" && @.san.type() == "string" && @.san != "")'
            )
        )
    ),
    -- negligible_action is one of the three wire values.
    CONSTRAINT policy_projections_negligible_action_check CHECK (
        (negligible_action = ANY (ARRAY['ignore'::text, 'warn'::text, 'block'::text]))
    )
);

ALTER TABLE ONLY public.policy_projections
    ADD CONSTRAINT policy_projections_pkey PRIMARY KEY (policy_id);

ALTER TABLE ONLY public.policy_projections
    ADD CONSTRAINT policy_projections_name_key UNIQUE (name);

CREATE INDEX idx_policy_projections_active_name
    ON public.policy_projections USING btree (name)
    WHERE (archived = false);

-- ---------------------------------------------------------------------------
-- exclusion_projections
-- ---------------------------------------------------------------------------

CREATE TABLE public.exclusion_projections (
    exclusion_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    cve_id text NOT NULL,
    package_pattern text,
    scope jsonb NOT NULL,
    reason text NOT NULL,
    -- Author attribution sourced from the event envelope
    -- (`actor_type = 'api'` carries the curator's `user_id`). NULL when
    -- the envelope actor is non-`api` (system / timer / gitops); the
    -- active-exclusions listing surfaces it on the `--actor` filter when
    -- set. Edited in place pre-1.0 (ADR 0022).
    added_by_actor_id uuid,
    -- Wall-clock timestamp the projection row was first written. Sourced
    -- from `now()` at INSERT time (the projector writes the row
    -- synchronously with the `ExclusionAdded` event append, so this is
    -- approximately the event's `stored_at` without paying an event-store
    -- join on every listing read). NOT NULL DEFAULT now() lets legacy
    -- projector code that omits this column continue to write (ON CONFLICT
    -- updates leave the original value alone). Edited in place pre-1.0
    -- (ADR 0022).
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone
);

ALTER TABLE ONLY public.exclusion_projections
    ADD CONSTRAINT exclusion_projections_pkey PRIMARY KEY (exclusion_id);

ALTER TABLE ONLY public.exclusion_projections
    ADD CONSTRAINT exclusion_projections_policy_id_fkey
    FOREIGN KEY (policy_id) REFERENCES public.policy_projections(policy_id) ON DELETE CASCADE;

CREATE INDEX idx_exclusion_projections_policy_id
    ON public.exclusion_projections USING btree (policy_id)
    WHERE (policy_id IS NOT NULL);

-- ---------------------------------------------------------------------------
-- retention_policy_projections (ADR 0020)
-- ---------------------------------------------------------------------------
--
-- Read-side projection of the event-sourced retention-policy aggregate
-- (StreamCategory::RetentionPolicy, DomainEvent::RetentionPolicyChanged
-- wrapping RetentionPolicyEvent). Mirrors policy_projections exactly in
-- shape and write contract: the gitops-authored RetentionPolicyUseCase
-- upserts this row in lockstep with each event append (append-then-upsert;
-- stream_version is the post-append AppendResult.stream_position, the
-- optimistic-concurrency anchor for the next mutation).
-- RetentionEvaluateHandler reads list_active() once per sweep instead of
-- replaying every stream.
--
-- Added IN PLACE in this squashed baseline (ADR 0022, NOT a new 016_*
-- migration). predicate/scope are JSONB serde of PolicyPredicate /
-- RetentionScope (both Serialize+Deserialize).

CREATE TABLE public.retention_policy_projections (
    policy_id          uuid NOT NULL,
    name               text NOT NULL,
    predicate          jsonb NOT NULL,
    scope              jsonb NOT NULL,
    archived           boolean DEFAULT false NOT NULL,
    stream_version     bigint NOT NULL,
    last_evaluated_at  timestamp with time zone,
    last_matched_count integer DEFAULT 0 NOT NULL,
    last_expired_count integer DEFAULT 0 NOT NULL,
    created_at         timestamp with time zone DEFAULT now() NOT NULL,
    updated_at         timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.retention_policy_projections
    ADD CONSTRAINT retention_policy_projections_pkey PRIMARY KEY (policy_id);

-- Partial-unique on active name: an archived row of the same name
-- does NOT collide with a re-declared policy (B1's terminal-archive
-- model — re-declaring an archived name mints a fresh policy_id;
-- there is no retention Reactivated event). Mirrors
-- idx_policy_projections_active_name.
CREATE UNIQUE INDEX idx_retention_policy_projections_active_name
    ON public.retention_policy_projections USING btree (name)
    WHERE (archived = false);
