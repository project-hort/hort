# 0014 — Externalised high-frequency timeseries

- **Status:** Accepted
- **Enforced by:** review + architecture — high-frequency counters (downloads) do not get a one-row-per-event relational table; the architect anti-pattern *download count in a relational table* is a review hard-block. Only summary endpoints remain in the relational store.
- **Supersedes:** —

## Context

The prototype recorded each download as a row in an `artifact_downloads` table. At registry scale that table grows without bound and its write rate competes with the serving path's own database — a high-frequency metric stored as discrete relational rows does not scale, and it drags an operational metrics concern into the system-of-record store.

## Decision

High-frequency metrics — download counts and similar — **leave the relational store**. They are emitted as metrics/timeseries (and `ArtifactDownloaded` is a high-volume domain event written to a separate stream, not interleaved with lifecycle events). The relational store keeps only **summary** endpoints (e.g. a materialised `repo_security_scores`-style projection for the CLI), not the per-event firehose.

## Consequences

- The relational store's write path is not contended by per-download inserts.
- Download analytics scale on a system built for high-cardinality timeseries, not on an OLTP table that grows forever.
- Per-artifact, per-download detail lives in tracing/timeseries; the relational layer answers "summary" questions, not "every event" questions.
- A new high-frequency counter must follow the same rule — no one-row-per-event table.

## Alternatives considered

- **Keep `artifact_downloads` (one row per download).** Rejected: unbounded growth and write contention on the system-of-record DB; this is the specific prototype scaling failure being removed.
- **Aggregate counters inline in the relational store (increment a column per download).** Rejected: still puts the high-frequency write on the OLTP path; externalising the timeseries keeps that load off the system of record.

## References

- The architect skill → Architectural Direction ("Externalised timeseries") and anti-pattern *download count in relational table*.
- `ArtifactDownloaded` event (separate high-volume stream); the `repo_security_scores` summary projection.
