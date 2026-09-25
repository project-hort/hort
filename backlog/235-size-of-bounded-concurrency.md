# 235 — The byte simulation calls `size_of` one target at a time

**Issue:** #293 · **Branch:** `agent/293-size-of-parallel`
**Governing decisions:** ADR 0003 (CAS / `StoragePort`) · #290 (the measured
bound, and the target dimension as the cost axis) · #280 (the inventory the
332 000 targets come from).

## Why

`crates/hort-app/src/task_handlers/retention_evaluate.rs`, the `Exact` arm of
the preview's byte simulation, is a plain sequential loop: one
`StoragePort::size_of(&hash).await` per target, fail-fast on the first error and
on `u64` overflow.

#290 measured the simulation's own cost at ~7 µs per target and set
`MAX_SIMULATION_TARGETS = 128_000` accordingly. The case that motivated the
whole path is above it: **`lila-fues` — 36 894 artifacts, ~332 000 targets,
~87 GB** (#280). The largest repository on the instance still reports
`freed_bytes: omitted`.

Raising the bound does not help, and that is now measured rather than assumed:

- **Filesystem** (`fs::metadata`): 8.4 µs per call. 332 000 targets ≈ 3 s.
- **Object store** (`object_store::head`, one HTTP HEAD per target): hours,
  sequentially, inside one task.

**The instance holding `lila-fues` runs S3** (Tom, 2026-09-25: staging is
filesystem, production S3). So it is exactly the unfavourable case. The loop is
the wall, not the database.

## Read first

- `crates/hort-app/src/task_handlers/retention_evaluate.rs` — the `Exact` arm,
  `MAX_SIMULATION_TARGETS`, `bound_omission_reason`, and the module doc's cost
  note (the ~7 µs/target figure and where it came from).
- `crates/hort-adapters-storage/src/object_store_backend.rs` — `size_of` (an
  `object_store` `head`), and how the store's HTTP client is built.
- `crates/hort-adapters-storage/src/filesystem.rs` — `size_of`.
- `crates/hort-domain/src/ports/storage.rs` — the port contract.

## What to build

Bounded concurrency over the loop. That is the whole change; the rest is the
care around it.

1. **Measure the limit, do not pick it.** #290 is the model: a number in the
   code with the measurement in the comment saying where it came from. Measure
   against **both** backends — the sandbox has a filesystem and a Garage
   sidecar. A concurrency that looks optimal against a local filesystem can run
   into throttling against S3.
2. **The ceiling must fit the adapter's own connection pool.** A
   `buffer_unordered(512)` against a client with a smaller pool produces waiting,
   not throughput; too large produces `503 SlowDown`. Read what the object-store
   client is actually configured with and derive the number from it rather than
   choosing a round one.
3. **The error semantics change and must be chosen deliberately.** Today the
   loop breaks on the first error and reports `omitted` with a reason; likewise
   on overflow. Concurrently, "the first error" is no longer deterministic. The
   *outcome* stays the same — `omitted` plus a reason, never a partial sum
   dressed as a measurement — but which reason wins is not. Decide and argue:
   first observed error, or a stable priority.

   **A partial sum must never be emitted as `exact`.** That is the one property
   with no acceptable failure mode.

   Note while you are there that a `NotFound` from `size_of` is reachable
   without anything being wrong — a blob can lose its last reference between the
   candidate read and the size probe. Say whether that should still collapse the
   whole preview to `omitted`; changing it is out of scope, but an unexamined
   answer is not.
4. **Touch `MAX_SIMULATION_TARGETS` last, if at all.** Whether it can rise above
   332 000 follows from your measurement plus #290's ~7 µs/target of database
   time (~2.3 s at 332 000). This item *may* raise it if the measurement carries
   it; it does not have to, and a raise without the measurement is exactly what
   #290 existed to stop.

## Explicitly not in this item

- No change to *what* is simulated — the candidate and refcount logic stands.
- **No blob-size cache.** `artifacts.size_bytes` exists but is the artifact's
  size, not the CAS content's, and the simulation counts freed content — that
  would be a different number under the same name. If this looks like a
  shortcut, the refutation belongs in the report.
- No change to the purge path.

## Acceptance

- The simulation over a realistic target set against an object store is an order
  of magnitude faster, with the measured figure in the report.
- The chosen concurrency is a justified named constant with the measurement in
  its comment — not a literal in a loop.
- A test: when a `size_of` fails, the result is `omitted` with a reason and
  **never** a partial sum as `exact`.
- A `u64` overflow test that still holds under concurrency.
- Gate green.
