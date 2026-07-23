# hort-http-discovery — Discovery HTTP Adapter

## Layer

Inbound HTTP — per-format-style adapter crate. No `hort-adapters-*`,
`sqlx`, or `reqwest` dependency (ADR 0008); the crate's own module doc
restates the invariant with a verification command. Requires >= 85%
coverage.

## Responsibility

Serves repo-keyed discovery (list package versions) and the self-service
prefetch trigger.

## Ports

- **Implements:** none — an inbound HTTP adapter.
- **Consumes:** `DiscoveryUseCase::list_versions`,
  `SelfServicePrefetchUseCase::enqueue_self_service`
  (`RepositoryAccessUseCase` is referenced only in tests).

## Key types

- `routes()` — mounts `GET /repositories`,
  `GET /repositories/:repo_key/discovery/versions/:package_name`,
  `POST /repositories/:repo_key/prefetch`.
- `dto`, `handlers`, `routes` — public modules.

## Rules

- ADR 0008, self-documented with a verification command.
- Both endpoints require an authenticated principal carrying
  `TokenKind::CliSession` — PATs and service-account tokens are rejected
  with 403, enforced inside the use case.
