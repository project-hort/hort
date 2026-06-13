# 0004 — Backend-agnostic EventStore port

- **Status:** Accepted
- **Enforced by:** the `EventStore` trait exposes only `append(batch: AppendEvents)`, `read_stream(stream_id, from, max_count)`, `read_category(...)`, `delete_stream(stream_id)`, and `archive_stream(stream_id, target)`; it carries no PostgreSQL-specific type. There is no `subscribe` method on the trait — in-process publish/subscribe fan-out is a separate `EventStorePublisher` concern in `hort-app`. The Postgres implementation lives in `crates/hort-adapters-postgres/src/event_store.rs` behind the trait.
- **Supersedes:** —

## Context

[0002](0002-event-sourced-artifact-lifecycle.md) makes the event log the system of record. The first implementation is PostgreSQL append-only tables, but a high-volume deployment may want a native event store (EventStoreDB/KurrentDB). If the event-store contract leaks PostgreSQL types (rows, pools, SQL) into the application layer, that future swap means rewriting callers, and the domain stops being I/O-agnostic ([0001](0001-hexagonal-zero-io-domain.md)).

## Decision

Define a single backend-agnostic `EventStore` port with optimistic-concurrency append, stream reads from a version, and category reads, plus delete and archive operations — and **no backend-specific leakage** in the trait. Both a PostgreSQL append-only-table adapter and a native-event-store adapter must be expressible behind the same trait. In-process publish/subscribe fan-out is handled by `EventStorePublisher` in `hort-app`, not by the port itself.

Optimistic concurrency is explicit: `append` takes an `AppendEvents` batch with an `expected_version`, so concurrent writers to the same stream conflict loudly rather than silently interleaving.

## Consequences

- The storage backend for events is a composition-root choice, not a code-wide assumption.
- The application layer depends on the trait, never on `sqlx` or a pool — keeping [0001](0001-hexagonal-zero-io-domain.md) intact.
- Backend-specific concerns (the seal/retention single-flight backstop, `pg_stat_activity` probes) live in the adapter, not the port — see [0020](0020-single-flight-seal-pool-backstop.md).
- A new backend must satisfy the full contract (append/read-stream/read-category/delete/archive + optimistic concurrency), not a convenient subset.

## Alternatives considered

- **Expose the `PgPool`/SQL directly to the application layer.** Rejected: fast to write, but welds the system to PostgreSQL and breaks the domain's I/O-agnosticism.
- **Two separate traits (one per backend).** Rejected: callers would branch on backend type, defeating the point of a port.

## References

- `crates/hort-domain/src/ports/` — the `EventStore` trait.
- `crates/hort-adapters-postgres/src/event_store.rs` — the PostgreSQL implementation.
- The architect skill → Outbound Port Contracts table.
