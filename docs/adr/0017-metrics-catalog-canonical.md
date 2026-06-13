# 0017 — The metrics catalog is canonical

- **Status:** Accepted
- **Enforced by:** `docs/metrics-catalog.md` is the single source of truth for every emitted metric name and label value; a metric or `result` value not in the catalog is a review hard-block. Result enums live with the emitting layer (never in `hort-domain`). High-cardinality labels are forbidden.
- **Supersedes:** —

## Context

Metrics that accrete ad hoc become an un-auditable, high-cardinality mess: every developer invents label names, an `artifact_id` or `user_id` label silently explodes cardinality and the monitoring bill, and nobody can enumerate what the system actually emits. Observability is a first-class requirement, so it needs a contract.

## Decision

`docs/metrics-catalog.md` lists every metric name, its labels, units, and `result` values. **No new metric name or label value may be introduced without updating the catalog in the same change.** Label names come from a fixed allowed set (`format`, `repository`, `result`, `backend`, `operation`, `category`, `reason`, `method`, `path`, `status`, `upstream`, `strategy`, `decision_point`, `rule`); anything else needs a catalog update first.

**Forbidden labels** (unbounded cardinality, hard block): `artifact_id`, `user_id`, `content_hash`, `stream_id`, concrete file paths, version strings. Per-instance detail goes to tracing spans / audit events. HTTP `path` must be the matched route template (`MatchedPath`), not the concrete URL. Sentinels (`repository="_all"`, `"unknown"`, `path="<unmatched>"`) cover the disabled/lookup-failed cases instead of leaking a UUID.

Result enums (`IngestResult`, `StorageResult`, `EventStoreResult`, `UpstreamErrorKind`) live in the layer that emits them — **not** a shared `hort-domain::metrics` module ([0001](0001-hexagonal-zero-io-domain.md): the domain has zero metric concerns). Each metric is emitted at exactly one layer (no double-counting).

## Consequences

- The full metric surface is enumerable from one file; a reviewer can reject an off-catalog label on sight.
- A cardinality-bomb label cannot ship — it is a named hard block.
- A small amount of result-enum duplication across adapters is accepted in exchange for keeping metric concerns out of the domain.

## Alternatives considered

- **Let metrics be defined inline wherever emitted.** Rejected: produces label drift and cardinality bombs with no audit surface.
- **A shared `hort-domain::metrics` module for result enums.** Rejected: drags tracing/metric concerns into the zero-I/O domain; enums belong with their emitter.

## References

- `docs/metrics-catalog.md`; `hort-app::metrics`, `hort-adapters-storage::metrics`, `hort-adapters-postgres::metrics`.
- The architect skill → Metrics section and the metric anti-patterns.
