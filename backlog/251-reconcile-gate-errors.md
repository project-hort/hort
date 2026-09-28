# 251 — the reconcile gate opens after an incomplete sweep

**Issue:** #321 · **Branch:** `agent/321-reconcile-gate-errors`
**Governing decisions:** ADR 0007 (fail-closed — "could not be determined" is
a hold, not a pass) · ADR 0028 (destructive-task idempotency; the gate exists
to keep the purge off an unconverged projection).

## Why

`RefcountReconcileUseCase::sweep_drift` accumulates per-repository failures
into `summary.errors` and returns `Ok(summary)` regardless
(`crates/hort-app/src/use_cases/refcount_reconcile_use_case.rs:111-131`).

The worker turns any `Ok` into an open gate
(`crates/hort-worker/src/composition.rs:1286-1295`):

```rust
Ok(summary) => {
    tracing::info!(
        repos_swept = summary.repos_swept,
        drift_repaired = summary.drift_repaired,
        errors = summary.errors,
        "refcount-reconcile boot sweep converged — RetentionPurgeHandler gate OPEN"
    );
    true
}
```

`summary.errors` is **logged and not read**. The operator sees `errors=1` and
`converged — gate OPEN` in the same line.

The adjacent `Err` branch (`:1296-1308`) already does the right thing — gate
CLOSED, fail-safe, boot does not abort — so the correct behaviour is present
and simply not reached when the sweep fails partially rather than wholly.

**Failure scenario.** A live artifact is missing its `primary_content` edge.
Boot reconciliation finds the gap, its repair insert fails, `errors` becomes 1,
the use case returns `Ok`, and the gate opens. A deleted sibling sharing that
hash is purged; after its edge goes, the count reads zero and the live
artifact's bytes are deleted. A failed repository scan produces the same
outcome.

## The inverse failure, which the fix must not create

Closing the gate on any error means a persistently failing repository keeps
the purge off **for ever** — and today a closed gate is visible only in one
boot log line, which scrolls away. There is no metric for the gate
(`docs/metrics-catalog.md` has no refcount-gate series).

So a closed gate has to be **discoverable while it persists**, not only at the
moment it is decided. Note the constraint: these are worker-side signals and
the worker `/metrics` listener is **disabled by default**
(`deploy/helm/hort-server/values.yaml`, `worker.metrics.enabled: false`), so a
gauge alone can be invisible in a real deployment. Whatever is chosen must
work without enabling that listener.

## Acceptance

- A sweep with `errors > 0` does **not** open the gate.
- The log line does not claim convergence that did not happen.
- A persistently closed gate is discoverable without enabling the worker
  metrics listener.
- A test covering the partial-failure path, not only the all-ok and the
  hard-`Err` paths.
- Gate green.
