# hort-http-npm — npm Registry HTTP Adapter

## Layer

Inbound HTTP — per-format adapter crate. No `hort-adapters-*`, `sqlx`, or
`reqwest` dependency (ADR 0008). Requires >= 85% coverage.

## Responsibility

Serves the npm registry HTTP API: scoped/unscoped packument GET, tarball
GET, and scoped/unscoped publish PUT.

## Ports

- **Implements:** none — an inbound HTTP adapter.
- **Consumes:** `RepositoryAccessUseCase`/`AccessLevel`, `IngestUseCase`
  (`DirectIngestRequest` on publish), `VirtualResolutionUseCase`,
  `ArtifactUseCase`, and — via `packument.rs` — `prefetch_trigger`.

## Key types

- `npm_routes()` / `npm_routes_with_publish_limit(limit)` — route table
  builders.
- `packument` (public) — same cross-crate-visibility rationale as
  `hort-http-cargo::index_cache`: `hort-formats-upstream`'s composition seam
  calls its `fetch_raw_with_cache`.
- `streaming_publish` (crate-private) — the base64 streaming decoder that
  replaced a ~525 MiB-per-publish buffering path.

## Rules

- ADR 0008: no `hort-adapters-*` / `sqlx` / `reqwest`; use-case-only data
  access.
- Protocol correctness is judged against the npm registry API spec, not the
  pre-existing implementation.
