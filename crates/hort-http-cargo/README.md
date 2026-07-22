# hort-http-cargo — Cargo Registry HTTP Adapter

## Layer

Inbound HTTP — per-format adapter crate. No `hort-adapters-*`, `sqlx`, or
`reqwest` dependency (ADR 0008). Requires >= 85% coverage.

## Responsibility

Serves the Cargo sparse-registry protocol (RFC 2789): `config.json`, the
sparse index (1/2/3/4+-char path tiers), tarball download, and publish.

## Ports

- **Implements:** none — an inbound HTTP adapter, not an outbound port.
- **Consumes:** `RepositoryAccessUseCase` (visibility/access checks),
  `IngestUseCase` (`DirectIngestRequest` on publish),
  `VirtualResolutionUseCase` (virtual-repo upstream resolution),
  `ArtifactUseCase`, and — via `index_cache.rs` — `prefetch_trigger`,
  `index_serve`/`index_serve_filter`, and `prefetch_use_case`.

## Key types

- `cargo_routes() -> Router<Arc<AppContext>>` — the crate's route table.
- `index_cache` — public specifically so `hort-formats-upstream`'s
  composition seam can call `fetch_raw_with_cache` for upstream index
  metadata.

## Rules

- ADR 0008: no `hort-adapters-*` / `sqlx` / `reqwest`; data access only
  through the use cases listed above, never `ctx.repositories`/`ctx.artifacts`
  directly.
- Protocol correctness is judged against RFC 2789 (the Cargo sparse-registry
  spec), not against the pre-existing implementation — per CLAUDE.md's
  "spec wins over implementation" rule.
