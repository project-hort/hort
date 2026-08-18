# hort-adapters-advisory-osv — OSV.dev Advisory Adapter

## Layer

Outbound adapter — leaf adapter with respect to the application layer
(`hort-app` used only for metrics-emission helpers, not use cases).
Requires >= 85% coverage.

## Responsibility

Implements advisory lookup against OSV.dev's `/v1/querybatch` batch
endpoint (per-SBOM-component queries, cached via `EphemeralStore`) and a
separate bulk-diff ingestion path (`pull_diff_since`) that pulls
per-ecosystem `osv-vulnerabilities` zip archives for the periodic
advisory-refresh tick.

`querybatch` returns abbreviated records — `id` and `modified` only — so
the query path resolves each distinct id to its full `/v1/vulns/{id}`
record (`hydrate.rs`) before deriving severity, otherwise the CVSS
scorer never sees a vector and every finding fails closed to `Critical`.
Hydrated records are cached on `(id, modified)`; hydration failure is
fail-soft, degrading that advisory to unscored rather than failing the
scan.

## Ports

- **Implements:** `AdvisoryPort` (`OsvAdvisoryAdapter`).
- **Consumes:** `hort_app::metrics::{emit_advisory_diff,
  emit_advisory_hydration, emit_advisory_query,
  observe_advisory_diff_duration, AdvisoryDiffResult,
  AdvisoryHydrationResult, AdvisoryQueryResult, UpstreamErrorKind}` —
  metric emission and error classification, not a use case.

## Key types

- `OsvAdvisoryAdapter` — `new(config, cache: Arc<dyn EphemeralStore>,
  extra_ca_anchors) -> DomainResult<Self>`.
- `OsvAdvisoryConfig` (has a documented `Default`).

## Rules

- `reqwest::Client::builder()` only, never `Client::new()` (ADR 0010) — the
  adapter's own doc comment cites the rule directly at its client
  construction site.
