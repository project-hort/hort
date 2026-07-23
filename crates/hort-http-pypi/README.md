# hort-http-pypi — PyPI Repository HTTP Adapter

## Layer

Inbound HTTP — per-format adapter crate. No `hort-adapters-*`, `sqlx`, or
`reqwest` dependency on the production edge (`hort-adapters-storage` and
`hort-adapters-ephemeral-memory` appear only under `[dev-dependencies]`, for
tests) (ADR 0008). Requires >= 85% coverage.

## Responsibility

Serves the PyPI Simple Repository API (PEP 503): twine upload, simple
root/project index, tarball/wheel download, and PEP 658 `.metadata`.

## Ports

- **Implements:** none — an inbound HTTP adapter.
- **Consumes:** `RepositoryAccessUseCase`/`AccessLevel`, `IngestUseCase`
  (`VerifiedIngestRequest::ProtocolNative` on upload), `ArtifactUseCase`,
  `ContentReferenceUseCase`, `PrefetchUseCase`, `VirtualResolutionUseCase`,
  `WheelMetadataUseCase`.

## Key types

- `pypi_routes()` / `pypi_routes_with_publish_limit(limit)` — route table
  builders.
- `simple_index` (public) — same cross-crate-visibility rationale as the
  other format crates' index caches, consumed by `hort-formats-upstream`.
- `metadata_endpoint` (crate-private) — PEP 658/491 `.metadata` support.

## Rules

- ADR 0008: no `hort-adapters-*` / `sqlx` / `reqwest` on the production
  dependency edge; use-case-only data access.
- Protocol correctness is judged against PEP 503 (Simple Repository API) and
  PEP 658 (`.metadata`), not the pre-existing implementation.
