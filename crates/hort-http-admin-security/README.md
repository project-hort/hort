# hort-http-admin-security — Admin Security-Score HTTP Adapter

## Layer

Inbound HTTP — per-format-style adapter crate for an internal admin surface
(not a third-party package-manager protocol). No `hort-adapters-*`, `sqlx`,
or `reqwest` dependency (ADR 0008) — the crate's own module doc states this
explicitly: "An adapter import here is a compile-time architectural
failure, NOT a review finding." Requires >= 85% coverage.

## Responsibility

Serves the admin security-score REST surface (get/list per-repository
scores) and the manual per-artifact rescan trigger.

## Ports

- **Implements:** none — an inbound HTTP adapter.
- **Consumes:** `SecurityScoreUseCase`, `ManualRescanUseCase`.

## Key types

- `routes()` — router builder (mounted with no prefix; the caller nests it
  under `/api/v1`).
- `dto`, `handlers`, `router` — public modules.

## Rules

- ADR 0008, self-documented in the crate's own module doc with the allowed
  dependency list spelled out.
- The rescan endpoint is gated by `Permission::Write` on the artifact's
  parent repository.
