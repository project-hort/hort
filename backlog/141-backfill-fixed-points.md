# 141 — Backfill fixed points: skipped items must leave candidacy

Issue: #211.

Both operator-triggered backfills share the starvation shape fixed in the
quarantine-release sweep: candidacy is `ORDER BY id LIMIT batch`, and a
skipped item writes nothing — so it never leaves candidacy nor its position
at the batch head. ≥ batch-size permanently-skipped rows with low ids ⇒ the
backfill silently never progresses past them while reporting `Completed`
with skip counts.

| site | batch | skip causes that strand |
|---|---|---|
| `crates/hort-app/src/task_handlers/wheel_metadata_backfill.rs` | 100 (cap 1000) | corrupt wheel ZIP, no METADATA member, oversized METADATA (`Ok(None)` / `Validation` silent-skip paths) |
| `crates/hort-app/src/task_handlers/oci_membership_edge_backfill.rs` | 100 (cap 1000) | CAS read failed, manifest did not parse, no config-role reference derived |

**Governing decisions:** the quarantine-release-sweep rotation precedent
(attempt cursor / durable exclusion), the `retention_candidate_reader`
keyset precedent (`after` cursor + `ORDER BY id`), ADR 0030 (migrations:
no destructive DDL; anything schema-touching is additive).

## Read first

- `crates/hort-app/src/task_handlers/wheel_metadata_backfill.rs` — the walk,
  the `Ok(None)`/`Validation` skip paths, the summary counters.
- `crates/hort-app/src/task_handlers/oci_membership_edge_backfill.rs` — same
  shape, its three skip causes.
- `crates/hort-adapters-postgres/src/retention_candidate_reader.rs` — the
  in-repo keyset model (`after` cursor + `ORDER BY id`) to mirror for the
  in-run advance.
- The candidacy queries the two handlers call (follow each handler's port to
  its adapter) — the `NOT EXISTS` shape they already use for "already
  backfilled".
- `crates/hort-app/src/use_cases/test_support.rs` — the hort-app mock
  harness for the handler tests.

## Confirmed design

Two mechanisms, each covering the failure mode the other cannot:

### 1. In-run keyset advance (fixes progress within a run)

Each backfill run walks batches with an in-memory keyset cursor: batches are
`WHERE id > last_seen ORDER BY id LIMIT batch`, where `last_seen` is the max
id of the *previous batch regardless of outcome* (processed, skipped, or
failed). A batch of 100% skips no longer causes the next batch to re-read the
same rows; a run always terminates after visiting every candidate at most
once. This mirrors `retention_candidate_reader` and needs no schema change.

### 2. Durable skip markers (fixes candidacy across runs)

A **structural** skip writes a marker `content_references` row —
`kind = 'wheel_metadata_skipped'` / `'oci_membership_skipped'` — and the
candidacy query's `NOT EXISTS` is extended to exclude marked rows, so a
structurally-unprocessable artifact leaves the pool permanently (no repeated
CAS reads / parse attempts on later runs).

**The transient/structural criterion decides which paths write a marker:**

- structural (marker written): corrupt wheel ZIP, no METADATA member,
  oversized METADATA; manifest did not parse, no config-role reference
  derived. Re-running cannot change these outcomes for the same bytes (CAS
  content is immutable).
- transient (NO marker — remains a candidate for the next run): CAS read
  failure, any storage/DB error. The in-run keyset advance (mechanism 1)
  already prevents such rows from blocking the current run.

An explicit operator param (`ignore_skip_markers: true` on the task params)
makes a re-run visit marked rows again — for the day a parser fix makes
previously-corrupt wheels readable. Default `false`.

### Reporting

Summary counters stay, split by cause bucket: processed, skipped_structural
(markers written), skipped_transient. No change to *what qualifies* as a
skip.

## Acceptance

- Per site: a fixture set of > batch-size permanently-skipped items with low
  ids plus one valid item behind them ⇒ the valid item is processed in the
  FIRST run (in-run advance), and the second run does not re-read the
  structural skips (markers).
- Transient-failure fixture: item is retried on the next run (no marker).
- `ignore_skip_markers` re-visits marked rows.
- Comment discipline: comments state the invariant (why a skip must leave
  candidacy), never issue/directive provenance.
- No destructive DDL; if any schema change turns out to be needed it is
  additive only (expected: none — `content_references` rows suffice).
