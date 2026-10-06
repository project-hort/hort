# 0004 — Backend-agnostic EventStore port

- **Status:** Accepted
- **Enforced by:** the `EventStore` trait exposes only `append(batch: AppendEvents)`, `read_stream(stream_id, from, max_count)`, `read_category(...)`, `read_categories(...)`, `health_check()`, `delete_stream(stream_id, authority)`, and `archive_stream(stream_id, target, authority)` (both returning `SealOutcome`, see the 2026-10-04 amendment); it carries no PostgreSQL-specific type. There is no `subscribe` method on the trait — in-process publish/subscribe fan-out is a separate `EventStorePublisher` concern in `hort-app`. The Postgres implementation lives in `crates/hort-adapters-postgres/src/event_store.rs` behind the trait.
- **Supersedes:** —

## Context

[0002](0002-event-sourced-artifact-lifecycle.md) makes the event log the system of record. The first implementation is PostgreSQL append-only tables, but a high-volume deployment may want a native event store (EventStoreDB/KurrentDB). If the event-store contract leaks PostgreSQL types (rows, pools, SQL) into the application layer, that future swap means rewriting callers, and the domain stops being I/O-agnostic ([0001](0001-hexagonal-zero-io-domain.md)).

## Decision

Define a single backend-agnostic `EventStore` port with optimistic-concurrency append, stream reads from a version, and category reads, plus delete and archive operations — and **no backend-specific leakage** in the trait. Both a PostgreSQL append-only-table adapter and a native-event-store adapter must be expressible behind the same trait. In-process publish/subscribe fan-out is handled by `EventStorePublisher` in `hort-app`, not by the port itself.

Optimistic concurrency is explicit: `append` takes an `AppendEvents` batch with an `expected_version`, so concurrent writers to the same stream conflict loudly rather than silently interleaving.

### Amendment 2026-10-04 — optimistic concurrency on the seal, not only the append

*Authorised by the answer on issue #336; implementing work on #335, finding
F19-6 of the #332 audit.*

The explicitness above covered the append and left the two **destructive**
operations without it. `delete_stream` / `archive_stream` therefore now take a
`SealAuthority` — the `stream_position` of the tail at which the caller's
terminality and retention-floor proof was read — and answer
`SealOutcome::NotAtProvenVersion`, removing nothing, when the stream has moved
since.

Proving a stream sealable and removing it are **two observations of a stream
that no lock holds still**, and the gap between them is not incidental: the
retention evaluation appends `ArtifactExpired` with `ExpectedVersion::Any`
against a candidate it read earlier, so a late event can land after the proof.
Without the check, a stream whose tail was no longer terminal was deleted under
a tombstone that described it perfectly — an audit record that is internally
consistent and silently wrong.

**There is no lock to take instead, and that is why this is the shape.** The
append path dropped `SELECT … FOR UPDATE` deliberately: [0009](0009-least-privilege-database-roles.md)
revokes table-level `UPDATE` from `hort_app_role`, so the locking read raised
42501 on every fresh-stream append. Appends serialise through the
`(stream_id, stream_position)` unique index — `migrations/004_events.sql` calls
it optimistic concurrency in as many words — so a seal has nothing to lock
against an appender either. The same discipline, applied to the same substrate.

A backend cannot satisfy the contract by accepting the parameter and ignoring
it. The condition must ride on the removal statement itself: under READ
COMMITTED a re-check phrased as its own statement cannot see an append that
commits before the removal begins, while the removal would take it.

[0020](0020-single-flight-seal-pool-backstop.md) does **not** cover this. Its
single-flight layers serialise seal *jobs* against each other; none of them
observes an appender.

**Residual, deliberately open.** An append committing after the removal
statement's snapshot is not reachable from inside that transaction — it
survives as the first event of a stream whose tombstone describes the events
before it, which the chain verifier reads as a `SealedGap` followed by live
events. That is what "after the seal" means anywhere in this system.

## Consequences

- The storage backend for events is a composition-root choice, not a code-wide assumption.
- The application layer depends on the trait, never on `sqlx` or a pool — keeping [0001](0001-hexagonal-zero-io-domain.md) intact.
- Backend-specific concerns (the seal/retention single-flight backstop, `pg_stat_activity` probes) live in the adapter, not the port — see [0020](0020-single-flight-seal-pool-backstop.md).
- A new backend must satisfy the full contract (append/read-stream/read-category/delete/archive + optimistic concurrency on **both** the append and the seal — see the 2026-10-04 amendment), not a convenient subset.

## Alternatives considered

- **Expose the `PgPool`/SQL directly to the application layer.** Rejected: fast to write, but welds the system to PostgreSQL and breaks the domain's I/O-agnosticism.
- **Two separate traits (one per backend).** Rejected: callers would branch on backend type, defeating the point of a port.

## References

- `crates/hort-domain/src/ports/` — the `EventStore` trait.
- `crates/hort-adapters-postgres/src/event_store.rs` — the PostgreSQL implementation.
- The architect skill → Outbound Port Contracts table.
