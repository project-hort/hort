# hort-http-events — Event Pull-Resync HTTP Adapter

## Layer

Inbound HTTP — per-format-style adapter crate. No `hort-adapters-*`,
`sqlx`, or `reqwest` dependency (ADR 0008); the crate's own module doc
restates the invariant with a verification command. Requires >= 85%
coverage.

## Responsibility

Serves `GET /api/v1/events` — a pull/long-poll resync surface over the
event store.

## Ports

- **Implements:** none — an inbound HTTP adapter.
- **Consumes:** no `hort-app` use case. This is the one crate in the
  inbound-HTTP layer that reaches the `EventStore` **port trait** directly
  (`Arc<EventStorePublisher>` on `AppContext`) rather than going through a
  use case — the crate's own doc calls this out explicitly as the only
  port it reaches for. Still ADR-0008-compliant (a port trait via
  `AppContext`, not an adapter import), just structurally different from
  the other ten `hort-http-*` crates.

## Key types

- `router()` — the single `GET /api/v1/events` route.
- `get_events` handler; `category_requires_admin` (delegates to
  `hort_domain::events::StreamCategory::requires_admin`).
- `dto`, `handler` — public modules.

## Rules

- ADR 0008, self-documented with a verification command.
- `AuthenticatedCaller` is required for every call; admin-only categories
  (`Policy`, `Authorization`, `User`, `Admin`, `AuthAttempts`) require
  `Permission::Admin`, everything else is filtered per-event.
