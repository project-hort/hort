# 0002 — Event-sourced artifact lifecycle

- **Status:** Accepted
- **Enforced by:** the artifact aggregate's state transitions are persisted only through appended domain events (`crates/hort-domain/src/events/`); the architect anti-pattern *state mutation via direct DB update bypassing the event log* is a review hard-block. Auxiliary CRUD (users, RBAC, repository config) deliberately does **not** go through the event store.
- **Supersedes:** —

## Context

Hort is a supply-chain control point: what entered quarantine, when it was released, who released it, what scan result was observed, and why a previously-rejected artifact became available are all audit-relevant facts. A mutable `status` column overwrites that history — it records the *current* state but not the sequence of decisions that produced it, and it cannot prove the sequence was legitimate.

The lifecycle is also genuinely a state machine (`ingested → quarantined → released | rejected | scan_indeterminate → promoted`) with security invariants on the transitions.

## Decision

Model all **artifact lifecycle** changes as immutable, append-only **domain events** — `ArtifactIngested`, `ChecksumVerified`/`ChecksumMismatch`, `ArtifactQuarantined`, `ScanRequested`/`ScanCompleted`, `ArtifactReleased`, `ArtifactRejected`, `Promotion*`, `Policy*`, `Exclusion*`, etc. Current state is a projection of the event stream. Events are immutable once appended.

**Policy definitions are event-sourced too**, not CRUD: adding a CVE exclusion or lowering a threshold can make a previously-rejected artifact available, so that decision and its authorship belong in the same append-only log as `ArtifactReleased`.

Auxiliary concepts that carry no such decision-history value — users, RBAC grants, repository configuration, API tokens — stay CRUD.

## Consequences

- The audit trail is the system of record, not a derived afterthought; tamper-evidence (event-chain sealing/verification) builds on this.
- Read paths require projections rather than reading a single row; this is the deliberate cost of an auditable history.
- "What changed and who authorised it" is answerable for every security-relevant transition by replaying the stream.
- The CRUD/event-sourced boundary must be chosen per concept: putting users in the event log, or putting `ArtifactReleased` in a mutable table, are both wrong.

## Alternatives considered

- **Mutable status columns + a separate audit-log table.** Rejected: two sources of truth that can disagree; the audit log can be bypassed by a direct `UPDATE`, which is the integrity gap event-sourcing closes.
- **Event-source everything, including users/RBAC.** Rejected: those concepts have no decision-history requirement and event-sourcing them adds projection complexity for no auditability gain.

## References

- `crates/hort-domain/src/events/` — event types, `events/chain.rs`, `events/mod.rs`.
- Outbound `EventStore` port — see [0004](0004-pluggable-eventstore-port.md).
- The architect skill's Event Vocabulary table and the anti-pattern *state mutation bypassing the event log*.
