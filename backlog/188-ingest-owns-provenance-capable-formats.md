# 188 — Ingest: the use case owns the provenance-capable format set (late-joiner clearance in every composition)

**Contract:** this file. Governing decisions: ADR 0039 §11 (verify-time cascade + late-joiner
self-clear are the only constituent release paths) and its 2026-09-12 amendment (an unsigned
hold is indefinite, so a missed clearance is permanent); ADR 0043 (per-child gating, cleared
via subject). The provenance-capable format set is version-static
(`hort_app::provenance::TIER1_PROVENANCE_CAPABLE_FORMATS`), already the single authority for
`validate_config` and gitops apply.

## The defect

`IngestUseCase::new` initialises `provenance_capable_formats` to an empty set, and
`resolve_late_joiner_clearance` returns early when the artifact's format is not in it. Only
`crates/hort-server/src/composition.rs` calls the opt-in builder
`with_provenance_capable_formats(TIER1…)`; `crates/hort-worker/src/composition.rs` builds its
own `IngestUseCase` (shared by `PrefetchIngestHandler`, `OciIndexChildIngestHandler`, seed
import) without it. Since eager child ingest moved index-child ingestion into the worker, a
child that lands after its subject's `ProvenanceVerified` is never self-cleared; under the
indefinite hold it stays `Quarantined` for good (release sweep: `skipped_provenance_pending`,
its blobs `held_parent_gated`). Observed as `quarantine/proxy-required-multilayer` steps
9a/9b timing out on both E2E lanes.

## Change

1. `IngestUseCase::new` sets `provenance_capable_formats` to
   `TIER1_PROVENANCE_CAPABLE_FORMATS` itself. Delete `with_provenance_capable_formats` and its
   single production call in `hort-server/src/composition.rs`. No composition may narrow or
   widen the set: it is a fact about the format registry, not about the caller.
2. Field doc states the invariant (one authority, every composition), no issue references.
3. Tests (hort-app, 100 % on touched branches, no DB):
   - new: `IngestUseCase::new` with no builder call runs the late-joiner clearance for an
     `oci` artifact under `Required` (asserts the cascade was consulted / the metric emitted —
     mirror the existing late-joiner tests' shape).
   - `a_non_capable_format_runs_no_late_joiner_clearance`: express "non-capable" through a
     non-Tier-1 format key (e.g. `npm`), not by emptying the set.
   - the other two gate tests (`verify_if_present…`, `a_permissive_policy…`) unchanged.
4. Nothing else: eager child ingest stays; the verify job's commit-then-cascade order already
   closes the race at the other end; #243 semantics untouched; worker composition untouched
   (it inherits the default).

## Acceptance

- Gate green (`cargo test --workspace`, clippy, fmt, audit, deny).
- Branch-first E2E on the human's harness: `./scripts/native-tests/run.sh --hort=compose
  --group quarantine` green (9a/9b pass), then the full run; worker log shows
  `provenance: late-joining constituent self-cleared from a verified subject` for
  eager-ingested children. MR only after that run is green.

## Out of scope

- Any change to eager child ingest fan-out or ordering.
- A worker-side re-drive for artifacts already stranded on a running deployment. Whether any
  exist on staging (a proxied multi-arch index under `provenance_mode: required`, children
  ingested by the worker after the subject verified) is a UAT question for the verifier after
  this lands, not an assumption; if the held set is non-empty it gets its own item.
