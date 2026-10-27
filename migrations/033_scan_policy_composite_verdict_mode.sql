-- Migration 033 — `ScanPolicy.composite_verdict_mode` (observed | promoted).
--
-- The unit of filesystem assessment for an OCI image is the image manifest,
-- not a layer: the config and the ordered layers are materialised as one OCI
-- layout and scanned as one image, because the package surface belongs to the
-- composition. A layer carrying a complete package database and no OS marker
-- reports nothing scanned on its own, so its isolated scan is evidence and the
-- composition's is the verdict (ADR 0064 D1/D2).
--
-- That composition is assessed on every manifest scan whatever this column
-- says. The column decides whether the resulting verdict reaches the artifact:
--   'observed' (default) — the composition is resolved, acquired, scanned and
--                          recorded as a `composite_scan_observations` row
--                          carrying both the composite verdict and the
--                          counterfactual, and the manifest's own assessment
--                          is byte-for-byte what it would be with no composite
--                          path at all. The behaviour of every policy written
--                          before this column existed.
--   'promoted'           — the composite verdict carries release authority:
--                          its findings join the manifest row's and reach the
--                          release gate under the existing predicate, and a
--                          composition that could NOT be produced is the
--                          absent verdict the scan axis fails closed on.
--
-- The `DEFAULT 'observed'` is load-bearing, not cosmetic: it is what makes
-- this an additive column for every existing row, and it mirrors
-- `CompositeVerdictMode::default()` in the domain layer. Promotion is an
-- operator act against named criteria and never something a release performs
-- on their behalf — a composite verdict adds rejections across an existing
-- estate, `Rejected` is terminal, and the periodic rescan never revisits it,
-- so a wrong verdict from a new analysis path on its first production run
-- leaves an estate only an explicit operator re-evaluation can recover
-- (ADR 0064 D6).
--
-- Unlike `enforcement` (019), a change to this column drives NO re-evaluation
-- of the already-assessed population: the continuous-enforcement pass
-- re-derives verdicts from *stored* findings, and a composite verdict's
-- findings come from scanning an assembled image. `promoted` -> `observed`
-- re-derived that way would un-reject a population with no fresh assessment,
-- which is the hazard that disqualified shipping this under
-- `ScanEnforcement::Record` in the first place.

ALTER TABLE public.policy_projections
    ADD COLUMN composite_verdict_mode text DEFAULT 'observed' NOT NULL;

-- composite_verdict_mode is one of the two wire values (mirrors the
-- enforcement / negligible_action / provenance_mode CHECK shape).
ALTER TABLE public.policy_projections
    ADD CONSTRAINT policy_projections_composite_verdict_mode_check CHECK (
        (composite_verdict_mode = ANY (ARRAY['observed'::text, 'promoted'::text]))
    );
