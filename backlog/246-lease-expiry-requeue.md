# 246 — A row abandoned in `running` is recovered by nothing

**Issue:** #306 · **Branch:** `agent/306-lease-expiry-requeue`
**Governing decisions:** #37 (the job-queue semantics) · ADR 0022 (append-only
migrations) · #6 / migration 015 (the *stranded-scan recovery* this sits beside
and must not duplicate).

## Why

A worker that dies holding a claimed row leaves it on `status = 'running'`
forever. Verified:

- Both claim queries select **`status = 'pending'`** only
  (`CLAIM_PENDING_BY_KINDS_SQL`, `claim_scan_jobs`). Their
  `locked_until IS NULL OR locked_until < now()` clause re-claims a *pending*
  row whose lease lapsed; it never sees a `running` one.
- `locked_until` is written in exactly **two** places in the workspace, both
  those claim statements (`… SET status='running', locked_by=$3,
  locked_until = now() + $4, attempts = attempts + 1`). **Nothing renews a
  lease mid-task.** The worker's 60-second heartbeat refreshes
  `scanner_registry.last_heartbeat`, not a job lease.
- There is no requeue path, no reaper, no re-drive.

## The gap has a neighbour, and the difference is the point

This is **not** the stranded-scan recovery. That mechanism already exists
(`RescanCandidateSelector::select_stranded`, migration 015) and covers the
*other* half: an artifact whose most recent `scan` job landed in `failed`, so
the sweep can re-enqueue once the scanner recovers. Migration 015's own comment
records that it deliberately requires **no in-flight `scan` job**, leaning on
`jobs_scan_unique` for that half.

So an abandoned `running` row falls exactly between the two: the claim query
will not take it (wrong status), and the stranded sweep will not route around
it (it counts as in-flight). Read both before designing; the new mechanism has
to fit beside them, not re-implement either.

## What it costs, per kind

For most kinds, nothing reads the row and an orphan is only clutter. Two kinds
are different:

- **`scan`** — `jobs_scan_unique` is `(artifact_id) WHERE kind='scan' AND
  status IN ('pending','running')`, so no further scan job for that artifact
  can ever be enqueued; and both rescan predicates exclude in-flight artifacts.
  The artifact becomes **permanently unscannable and unrescannable**, silently.
- **`provenance-verify`** — `find_active_provenance_for_artifact` has the same
  `status IN ('pending','running')` shape and therefore the same trap.

One dead worker, one stranded artifact per in-flight row, accumulating.

## The hard question: what distinguishes a dead worker from a slow task

The only signal is `locked_until < now()`, and today it means *both* "the
worker died" and "the task is slower than its lease" (default 900 s,
`HORT_SCANNER_LOCK_DURATION_SECS`). Requeueing on that alone runs the same task
twice.

Two routes, and the choice is to be argued:

1. **Renew the lease.** A running handler extends `locked_until` periodically;
   then an expired lease means "dead" unambiguously. Clean, but it touches the
   dispatcher or every handler that runs long.
2. **A per-kind grace multiple.** No new mechanism, but the number is a guess,
   and for a kind with no known upper bound there is no right one.

**Establish per kind whether a double run actually harms** before choosing — an
idempotent sweep does not care, a scan with side effects might. That census is
part of the work, not a preliminary to it.

## Two constraints the design must respect

- **`attempts` is incremented by the claim itself.** A requeued row will be
  claimed again and counted again, so the interaction with the retry budget
  (`HORT_SCANNER_MAX_ATTEMPTS` for scan) has to be deliberate: a repeatedly
  crashing task must not be requeued forever.
- **Deleting a `running` row is not an option.** It may be genuinely running,
  and its completion would then land on nothing (`mark_completed` updates zero
  rows). For `staging-sweep` specifically that would destroy the liveness
  breadcrumb another unit exists to preserve.

## Acceptance

- A row abandoned in `running` becomes claimable again, for **every** kind —
  not only the cheap one.
- The discriminator is argued: lease renewal, or a per-kind grace with its
  derivation.
- The per-kind double-run census is in the report; where a double run harms, it
  is excluded.
- `attempts` and the retry budget behave definedly after a requeue.
- A metric counts requeues, so a frequently-dying worker is visible rather than
  silently compensated.
- A test showing an artifact with an abandoned `scan` row is scannable again
  afterwards.
- Gate green; `#[serial(hort_pg_db)]` on every test that acquires a connection.

## Explicitly not in this item

- No change to `select_stranded`, to `jobs_scan_unique`, or to the rescan
  predicates.
- No deletion of non-terminal rows.
- No change to the terminal-row horizons.
