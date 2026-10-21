-- 032_composite_scan_observations.sql
--
-- The shadow composite-scan observation projection (ADR 0064 D6).
--
-- The composed assessment of an OCI image manifest carries no release
-- authority. It is produced, compared against what the manifest's own
-- bytes concluded, and recorded here so that "across this estate, what
-- would promoting the composite verdict have changed?" is a query rather
-- than an exercise in reading a log aggregator before its retention
-- expires. That question is the promotion criterion; this table is what
-- makes it answerable.
--
-- ## Why a table and not an event
--
-- The artifact's event stream is where release authority is derived
-- from. A shadow verdict appended there is a verdict a future reader can
-- mistake for one that counts, and the stream's consumers are exactly
-- the code that must never see it. A projection keeps the two apart by
-- construction, and keeps this path clear of the canonical-bytes hazard
-- an additive event field carries.
--
-- ## One row per artifact, replaced
--
-- The promotion question is about the estate's current state, so the
-- artifact id is the primary key and each assessment overwrites. An
-- append-only per-scan history would grow without bound on a population
-- the rescan cadence revisits daily, with no retention story to bound
-- it. This way the table is bounded by the artifact population and each
-- row leaves with its artifact.
--
-- ## What is not here
--
-- Not the composite findings themselves. A findings blob is a CAS
-- object, a CAS object needs a `content_references` claim to survive
-- garbage collection, and a claim written by a path that must carry no
-- authority is the start of exactly the entanglement this is designed to
-- avoid. The distinct vulnerability ids plus the exact counts answer the
-- promotion question; the full report is reproducible by re-running the
-- scan.
--
-- Expansion only: a new table. No existing identifier is removed,
-- renamed or narrowed (ADR 0030), so this needs no `CONTRACTIONS.toml`
-- entry.
--
-- GRANTs / role wiring: none explicit. The post-004 convention (ADR
-- 0009) is that the operator's role bootstrap carries
-- `ALTER DEFAULT PRIVILEGES … GRANT SELECT, INSERT, UPDATE, DELETE ON
-- TABLES TO hort_app_role`, so a table created by the migration role is
-- reachable by the runtime role without a per-migration GRANT.

CREATE TABLE public.composite_scan_observations (
    -- One row per manifest artifact; a reassessment replaces it.
    artifact_id     UUID        PRIMARY KEY
        REFERENCES public.artifacts(id) ON DELETE CASCADE,
    -- Denormalised so the promotion question can be asked per
    -- repository without a join to a table the query does not otherwise
    -- need.
    repository_id   UUID        NOT NULL
        REFERENCES public.repositories(id) ON DELETE CASCADE,
    -- The manifest's own content hash — the composition's identity.
    -- Present on every outcome, including the refusals: the manifest
    -- row's payload is the one document the composite path always has.
    manifest_digest CHAR(64)    NOT NULL,
    -- The backend that answered, NULL when none did.
    scanner         TEXT,
    observed_at     TIMESTAMPTZ NOT NULL,

    -- Which of the four outcomes this run reached. Mirrors
    -- `CompositeAssessment::as_str` in
    -- crates/hort-domain/src/ports/composite_scan_observation.rs.
    assessment      TEXT        NOT NULL,
    -- Why, for the three outcomes that are not `assessed`. May quote a
    -- parse's or an upstream's own complaint, so it is bounded.
    reason          TEXT,

    -- What acquiring the composition cost. These fetches are egress an
    -- operator did not ask for: the composite path pulls a proxy image's
    -- absent layers in order to assess it, and an operator deciding
    -- whether to promote the verdict is also deciding whether to keep
    -- paying for it. Stored beside the verdict they bought.
    already_present BIGINT      NOT NULL,
    fetched         BIGINT      NOT NULL,
    fetched_bytes   BIGINT      NOT NULL,

    -- Severity counts of the composite findings, exact.
    severity_critical   BIGINT  NOT NULL,
    severity_high       BIGINT  NOT NULL,
    severity_medium     BIGINT  NOT NULL,
    severity_low        BIGINT  NOT NULL,
    severity_negligible BIGINT  NOT NULL,

    -- Exact totals. `distinct_vulnerability_count` may exceed the length
    -- of `vulnerability_ids`: the cap below is on the stored list only.
    finding_count                BIGINT NOT NULL,
    distinct_vulnerability_count BIGINT NOT NULL,
    vulnerability_ids            TEXT[] NOT NULL DEFAULT '{}'::text[],

    -- Both columns are the **same gate's decision over a finding set**,
    -- which is exactly what makes them comparable. Neither is this
    -- artifact's disposition: that lives in
    -- `artifacts.quarantine_status`, joinable on `artifact_id`, and is
    -- deliberately not restated here.
    --
    -- The counterfactual: what the release gate would have decided over
    -- the composite findings, had the composite verdict carried
    -- authority. NULL unless the composition was assessed — there is
    -- nothing to decide on otherwise.
    composite_findings_decision TEXT,
    -- What the same gate, with the same policy and the same exclusion
    -- set, decided over the findings the primary axis produced on the
    -- same run. The other half of the comparison, in the same row, so
    -- the promotion question is a single-row read.
    --
    -- Not "what the artifact got". A run in which every backend
    -- abstained in a release-gating way produces an empty primary
    -- finding list, so this column reads `clean` while the artifact is
    -- held `scan_indeterminate`; a column of `clean` here is a column
    -- of gate decisions over empty finding lists, not an estate that is
    -- fine.
    primary_findings_decision   TEXT     NOT NULL,

    CONSTRAINT composite_scan_observations_manifest_digest_shape
        CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT composite_scan_observations_assessment_known
        CHECK (assessment IN ('assessed', 'nothing_to_compose',
                              'deterministic_refusal', 'transient_refusal')),
    -- Only an assessed composition has a counterfactual. A refusal
    -- carrying one would be a decision about findings nobody produced.
    CONSTRAINT composite_scan_observations_counterfactual_needs_assessment
        CHECK (composite_findings_decision IS NULL OR assessment = 'assessed'),
    CONSTRAINT composite_scan_observations_composite_findings_decision_known
        CHECK (composite_findings_decision IS NULL
               OR composite_findings_decision IN ('clean', 'findings_recorded', 'reject')),
    CONSTRAINT composite_scan_observations_primary_findings_decision_known
        CHECK (primary_findings_decision IN ('clean', 'findings_recorded', 'reject')),
    -- Every count is a `u32` in the domain; BIGINT with an explicit
    -- ceiling is how this schema already carries one (migration 026's
    -- `refs_remaining`).
    CONSTRAINT composite_scan_observations_counts_in_u32
        CHECK (already_present BETWEEN 0 AND 4294967295
           AND fetched         BETWEEN 0 AND 4294967295
           AND severity_critical   BETWEEN 0 AND 4294967295
           AND severity_high       BETWEEN 0 AND 4294967295
           AND severity_medium     BETWEEN 0 AND 4294967295
           AND severity_low        BETWEEN 0 AND 4294967295
           AND severity_negligible BETWEEN 0 AND 4294967295
           AND finding_count                BETWEEN 0 AND 4294967295
           AND distinct_vulnerability_count BETWEEN 0 AND 4294967295),
    CONSTRAINT composite_scan_observations_fetched_bytes_non_negative
        CHECK (fetched_bytes >= 0),
    -- Mirrors MAX_OBSERVED_VULNERABILITY_IDS. A deliberately-constructed
    -- image has no natural bound on its advisory count, and this column
    -- is written by a path nobody asked to run.
    CONSTRAINT composite_scan_observations_ids_bounded
        CHECK (cardinality(vulnerability_ids) <= 256),
    -- The stored list is the truncation of the exact count, never larger
    -- than it.
    CONSTRAINT composite_scan_observations_ids_are_a_truncation
        CHECK (cardinality(vulnerability_ids) <= distinct_vulnerability_count),
    CONSTRAINT composite_scan_observations_distinct_within_findings
        CHECK (distinct_vulnerability_count <= finding_count)
);

COMMENT ON TABLE public.composite_scan_observations IS
    'Shadow composite-scan assessment per manifest artifact. Carries no release authority.';

-- PostgreSQL does not index a foreign key automatically, and
-- `repositories` rows are deleted. Without this the cascade sequentially
-- scans the table, and the per-repository promotion query has nothing to
-- read through either.
CREATE INDEX composite_scan_observations_repository_id_idx
    ON public.composite_scan_observations (repository_id);
