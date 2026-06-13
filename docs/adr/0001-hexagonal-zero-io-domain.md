# 0001 — Hexagonal architecture with a zero-I/O domain layer

- **Status:** Accepted
- **Enforced by:** dependency graph — `hort-domain/Cargo.toml` carries no `sqlx`, `reqwest`, `axum`, `hyper`, or runtime-I/O dependency; a domain module that imports one fails to compile. Reinforced by the architect review checklist ("Domain layer has zero I/O imports").
- **Supersedes:** —

## Context

The prototype (`backend/`) interleaved HTTP handling, business rules, and SQL in the same modules. Handlers built storage paths, ran queries, and made authorization decisions inline. That made the security-critical logic (quarantine invariants, CAS guarantees, policy evaluation) impossible to test in isolation and impossible to reason about without also holding the database and HTTP layers in mind.

The rewrite needed a structure where the rules that matter for security and correctness are pure, exhaustively testable, and independent of any particular database, storage backend, or transport.

## Decision

Layer the system as an onion: a pure **domain layer** (`hort-domain`) with zero I/O at its centre, an **application layer** (`hort-app`) that orchestrates the domain through outbound port traits, **adapters** that implement those ports against real infrastructure, and **inbound adapters** (HTTP/gRPC/CLI) that translate requests into application calls.

The domain layer contains entities, value types, domain events, and state machines only. It must not depend on `sqlx`, `reqwest`, `axum`, or any I/O runtime. Outbound dependencies are expressed as **port traits** that the domain/application drives; concrete I/O lives exclusively in the adapter crates.

## Consequences

- `hort-domain` and `hort-app` are required to hold **100% test coverage** — every branch is reachable with pure inputs, so there is no excuse for an untested path. This is the project's security boundary.
- Infrastructure can be swapped (Postgres ↔ a native event store, filesystem ↔ S3) without touching domain logic.
- It costs an explicit port-trait + adapter for every external interaction, rather than a direct call. This indirection is deliberate and is not to be "optimised away" by letting the domain reach for a concrete adapter.
- The dependency direction is load-bearing: it is a compile error, not a convention, for the domain to depend on an adapter.

## Alternatives considered

- **Keep the prototype's layered-but-leaky structure (services calling SQL directly).** Rejected: it was the specific thing that made the prototype untestable and unauditable; "it works" is not "it is correct".
- **A traditional N-tier split (controllers → services → repositories) without the zero-I/O rule.** Rejected: without the structural ban on I/O in the core, the security logic drifts back into being entangled with the database, which is exactly the failure mode being removed.

## References

- `crates/hort-domain/` (entities, events, ports, policy) — no I/O dependencies in `Cargo.toml`.
- `crates/hort-app/` — orchestration over `Arc<dyn _Port>`s.
- `CLAUDE.md` → "Architectural Direction" and "Test Coverage Tiers".
- The architect skill's anti-pattern: *SQL in a domain entity* / *domain calling adapters*.
