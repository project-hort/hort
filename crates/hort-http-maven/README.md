# hort-http-maven — Maven/Gradle Repository HTTP Adapter

## Layer

Inbound HTTP — per-format adapter crate. No `hort-adapters-*`, `sqlx`, or
`reqwest` dependency (ADR 0008) — `sha1`/`sha2`/`md-5`/`hex` are pure
hashing crates, not adapters, and are explicitly permitted for checksum
sidecar generation. Requires >= 85% coverage.

## Responsibility

Serves the Maven/Gradle repository layout — GAV-coordinate paths,
server-generated `maven-metadata.xml`, and checksum sidecars — for a single
wildcard-tail route (`/maven/{repo_key}/*artifact_path`). Scope is
currently Hosted repositories only.

## Ports

- **Implements:** none — an inbound HTTP adapter.
- **Consumes:** `RepositoryAccessUseCase`/`AccessLevel`, `IngestUseCase`
  (`ingest_direct`/`DirectIngestRequest`), `VirtualResolutionUseCase`,
  `ArtifactUseCase`, and — via `serve.rs` — `index_filters`, `index_serve`,
  `index_serve_filter`.

## Key types

- `maven_routes()` — the crate's single route-table builder.
- `serve`, `sidecar`, `upstream_pull` (crate-private) — GAV resolution,
  checksum sidecar generation, and upstream pull-through.

## Rules

- ADR 0008: no `hort-adapters-*` / `sqlx` / `reqwest`; use-case-only data
  access.
- Auth posture is anonymous-by-default reads, gated only by the use case's
  visibility filter — not a protocol-mandated auth scheme, since Maven has
  no equivalent to npm/PyPI's publish-token conventions.
