# 168 — one statement, not a thousand: batch the child-ingest enqueue off the request path

**Issue:** #229 · **Branch:** `agent/229-eager-child-ingest` · Item 5 of 5
(depends on items 161, 162 and 167; one MR carries all of them).

## Problem

Item 2's enqueue is awaited serially inside the leader's coalescing closure:
one `enqueue_task` round-trip per declared child, up to
`MAX_INDEX_CHILDREN = 1024`, all before the client's manifest response is
produced, and all with the pull-dedup coalescing window held open. Other
clients pulling the same index wait behind it.

The issue's D2 says the child *fetches* stay off the request path, and they do.
The *enqueues* did not follow, and a thousand serial INSERTs is the same
latency mistake in a different place.

This is not hypothetical arithmetic: the whole point of the feature is fresh
multi-arch indexes, which is exactly when every child is new and every INSERT
is a real write rather than a conflict.

## Governing decisions

- **ADR 0053** already reached this conclusion for the cascade and wrote the
  reasoning down verbatim on `JobsRepository::enqueue_prefetch_batch`: a
  per-row entry point for a cohort means either N round-trips of latency and
  lock churn, or N individually-swallowed conflict errors, and the
  batch-with-`ON CONFLICT` contract bundles both wins into one statement.
  The same argument applies here unchanged.
- **Issue #229 D2** — the enqueue itself stays synchronous and durable. Do not
  make this a `tokio::spawn`: a spawned enqueue can be lost, and a lost enqueue
  is precisely the failure mode D2 rejected. One statement on the request path
  is fine; a thousand is not.

## Read first

- `crates/hort-domain/src/ports/jobs_repository.rs` — `enqueue_task`,
  `enqueue_prefetch_batch` and especially the "Why a separate entry point"
  doc block, which is the rationale this item reuses.
- `migrations/009_scan_jobs_and_findings.sql` — `jobs_idempotency_key_uq`
  (unscoped over all non-`NULL` keys) and the `prefetch%`-scoped `target_key`
  partial unique index. Note the asymmetry: `enqueue_prefetch_batch` conflicts
  on the latter and is therefore **not** reusable for this kind.
- `crates/hort-app/src/use_cases/oci_index_child_enqueue.rs` — the per-child
  loop to replace.
- `crates/hort-adapters-postgres/` — the `enqueue_prefetch_batch`
  implementation, as the shape to mirror.

## What to build

A batched enqueue keyed on `idempotency_key`, and the facade using it.

- Add the port method alongside `enqueue_prefetch_batch`, conflicting on
  `jobs_idempotency_key_uq` rather than `target_key`. Give it the same default
  implementation treatment the existing batch method has, so pre-existing test
  fixtures keep compiling.
- The facade builds all rows and issues **one** statement. A conflict is
  absorbed by the index, not surfaced per row and swallowed in a loop.
- Failure behaviour is unchanged: the statement failing is logged and counted,
  and cannot fail the pull. The client still gets its normal response and the
  children still reach the repository through the lazy path.
- The handler's grandchild recursion should use the same batched entry point.
  It enqueues a cohort for the same reason.

## The retention sweep must be on by default

Item 167 brought terminal `oci-index-child-ingest` rows under
`prefetch-row-retention-sweep`, but that sweep ships
`scheduledTasks.prefetchRowRetentionSweep.enabled: false`. Its justification —
"the cascade is opt-in per repository, so if no repo opts in the table
accumulates nothing" — stopped being true the moment this kind joined it.
These rows accrue on **any** OCI proxy repository with no opt-in at all, one
per declared child manifest per index pull-through.

So under the shipped default, item 167's stated problem is fixed only for
operators who had already enabled a sweep for an unrelated feature. A fix that
requires an unrelated opt-in is not a fix.

Flip the default to `true`. The precedent is exact:
`scanRowRetentionSweep` ships enabled and is justified as "every artifact scan
leaves a terminal row from day one" — which is now word for word the situation
here. The blast radius is small in the other direction too: an operator who
never enabled the cascade has no `prefetch%` rows for the sweep to touch, so
flipping costs them one idle CronJob and gains them the bound they cannot
otherwise get.

`scripts/test-helm-templates.sh` pins the rendered CronJob count together with
an explicit "stay default-disabled" rationale. Both must move in the same
change, and the rationale must be rewritten rather than deleted — the next
reader needs to know why it is on, not merely that the number changed.

**`helm` is not installed in the toolchain container**, so this is the one part
of the change that cannot be verified locally. Say so plainly in the report;
the branch pipeline is the verification, and a red `test-helm-templates` job
there is the expected failure mode if the pinned count is wrong.

## Two smaller things in the same file

- `IndexChildEnqueueSummary` is returned and then discarded at all three
  production call sites, so its documented "for the caller's log line" purpose
  is unrealised. Either log it at the call sites or stop returning it. Pick
  one and say which in the commit body.
- `is_empty()` conflates "no children declared" with "body refused or
  over-cap". The internal `warn!` distinguishes them but no caller can. If the
  summary survives the previous point, make the distinction visible in it.

## Explicitly not in this item

- Moving the enqueue to a `tokio::spawn` or any fire-and-forget shape.
- Any change to the dedupe key, the presence check, or the failure-shape split.
- Any change to `enqueue_prefetch_batch` or the cascade's use of it.
- Reusing the `prefetch%`-scoped `target_key` index for this kind. It does not
  apply and forcing it would mean renaming the kind.

## Acceptance

- A pull of an index with N declared children issues **one** enqueue statement,
  not N. Pin it with a mock assertion on the call count, so a later refactor
  back to a loop fails a test rather than passing quietly.
- A repeat pull still adds no rows, now by index conflict rather than by
  per-row error swallowing.
- A batch-statement failure leaves the pull's response unchanged.
- The DB-gated adapter test proves the real conflict behaviour against a real
  Postgres, alongside the existing single-row proof.
- Full local gate green per the pre-push checklist, `cargo test --workspace`.
