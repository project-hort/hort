# hort-http-subscriptions — Subscriptions HTTP Adapter

## Layer

Inbound HTTP — per-format-style adapter crate. No `hort-adapters-*`,
`sqlx`, or `reqwest` dependency (ADR 0008); the crate's own module doc
restates the invariant with a verification command. Requires >= 85%
coverage.

## Responsibility

Serves `/api/v1/subscriptions`: create, list-own, get, update
(pause/resume), delete, plus an admin list-all route.

## Ports

- **Implements:** none — an inbound HTTP adapter.
- **Consumes:** `SubscriptionUseCase`.

## Key types

- `router()` — route table (absolute path strings, since composition uses
  `Router::merge` rather than `nest`).
- `CreateSubscriptionRequest` / `UpdateSubscriptionRequest` /
  `SubscriptionError` — request/error DTOs.
- `dto`, `error`, `handlers` — public modules.

## Rules

- ADR 0008, self-documented with a verification command.
- Per-id/own routes use the `AuthenticatedCaller` extractor with
  owner-or-admin enforced inside the use case; the admin-list route uses
  `AdminPrincipal`.
