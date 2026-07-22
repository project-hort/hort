# hort-adapters-ephemeral-redis — Redis Ephemeral Store

## Layer

Outbound adapter — leaf adapter with respect to the application layer
(same `EphemeralKeyspaceClass`-only `hort-app` dependency as the in-memory
adapter). Requires >= 85% coverage.

## Responsibility

Multi-node-safe implementation of the `EphemeralStore` port over Redis (via
the `fred` client), using Lua `EVAL` scripts so version-bump + value-write +
TTL-refresh are atomic per operation — the production choice when replicas
must share upload-session state.

## Ports

- **Implements:** `EphemeralStore`, by `RedisEphemeralStore` and the same
  `MeteredEphemeralStore<T>` decorator pattern as the in-memory adapter.
- **Consumes:** none beyond the `EphemeralKeyspaceClass` data type.

## Key types

- `RedisEphemeralStore` — fallible `connect(url: &str) -> DomainResult<Self>`.
- `MeteredEphemeralStore<T>`.

## Rules

- Same `EphemeralKeyspaceClass`/keyspace-registry discipline as
  `hort-adapters-ephemeral-memory`.
- A `redis-integration-tests` Cargo feature gates DB/broker-requiring tests
  off the default `cargo test` run, consistent with the project's
  self-skipping DB-gated-test discipline.
