# 0020 — Single-flight backstop for the unbounded seal/retention append

- **Status:** Accepted
- **Enforced by:** layered single-flight (CronJob `concurrencyPolicy: Forbid` + worker per-kind semaphore `concurrency=1` + per-UTC-day idempotency key + sequential `seal_one` await) plus a connection-level `lock_timeout` backstop on both worker pools. Relaxing any layer protecting `seal_and_remove`'s unbounded `StreamSealed` append is a hard block pending co-review.
- **Supersedes:** —

## Context

`seal_and_remove` appends an unbounded `StreamSealed` tombstone to the `admin-eventstore-retention` stream. That append has **no internal wait bound** — it is safe only because at most one `seal_and_remove` runs cluster-wide at a time. The safety is delivered by several independent layers; if any is silently relaxed (a manual task invocation racing the CronJob, a second `StreamSealed` emitter, a weakened idempotency key, `concurrencyPolicy: Allow`), the unbounded-block failure mode re-opens.

## Decision

The unbounded append is protected by **defence in depth**: (1) the `eventstore-archive` CronJob's `concurrencyPolicy: Forbid`; (2) the worker per-kind semaphore (`concurrency=1`); (3) the per-UTC-day idempotency key; (4) the sequential `seal_one` await. As a connection-level backstop, both worker Postgres pools carry a **`lock_timeout`** (`HORT_WORKER_LOCK_TIMEOUT_MS`, default 120000 ms) — bounding only lock-acquisition wait, never aborting a legitimately slow large-stream `DELETE`.

Relaxing **any** single-flight layer is a hard block pending co-review. Setting the timeout to `0` (disables the backstop on both pools), substituting `statement_timeout` for `lock_timeout`, or applying the bound to only one of the two pools are all forbidden without the recorded rationale.

## Consequences

- The unbounded append cannot block the cluster, because it is never concurrent with itself.
- The `lock_timeout` is a backstop, not a substitute for the single-flight precondition — it catches the pathological contended-slot case without aborting honest slow deletes.
- Any change to the seal/retention single-flight layers carries a security co-review obligation, by rule.

## Alternatives considered

- **Bound the append internally (chunked / time-limited).** Rejected at present: the single-flight + backstop model is simpler and matches the production single-writer reality; an internal bound would be a larger change to the append path.
- **`statement_timeout` instead of `lock_timeout`.** Rejected: it would abort legitimately slow large-stream deletes; `lock_timeout` fires only on lock-acquisition contention.

## References

- `crates/hort-adapters-postgres/src/event_store.rs` (`StreamSealed` emitter); worker pool wiring (`HORT_WORKER_LOCK_TIMEOUT_MS`).
- `deploy/helm/hort-server/templates/cronjob-eventstore-archive.yaml` — the `concurrencyPolicy: Forbid` layer.
- The architect skill → the seal-pool single-flight review checklist.
- [0028](0028-destructive-task-idempotency.md) — the durable idempotency layer.
