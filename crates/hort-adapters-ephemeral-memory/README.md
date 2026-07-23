# hort-adapters-ephemeral-memory — In-Process Ephemeral Store

## Layer

Outbound adapter — leaf adapter with respect to the application layer
(`hort-app` is depended on only for the `EphemeralKeyspaceClass` value
type). Requires >= 85% coverage.

## Responsibility

In-process, single-node implementation of the `EphemeralStore` port: a
`DashMap`-backed key/value store with per-key CAS mutexes and a background
TTL evictor. Used for dev/test/single-node deployments where the Redis
adapter's cross-replica consistency isn't needed.

## Ports

- **Implements:** `EphemeralStore`, by `InMemoryEphemeralStore` and the
  `MeteredEphemeralStore<T: EphemeralStore>` decorator (wraps any
  `EphemeralStore` to add metrics).
- **Consumes:** none beyond the `EphemeralKeyspaceClass` data type.

## Key types

- `InMemoryEphemeralStore`.
- `MeteredEphemeralStore<T>` — `new(inner: Arc<T>, class:
  EphemeralKeyspaceClass)`.

## Rules

- Every `MeteredEphemeralStore` construction site must tag its
  `EphemeralKeyspaceClass` (`evictable`/`durable`) so metric series carry
  the right label — feeds the `ephemeral_keyspace_exhaustive` structural
  guard test (CLAUDE.md Pre-push Quality Checklist).
