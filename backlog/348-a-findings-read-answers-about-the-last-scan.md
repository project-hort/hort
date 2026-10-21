# 348 — A findings read answers about the last scan

**Issue:** #360 · **Branch:** `agent/360-findings-read-the-last-scan`
**Governing decisions:** ADR 0007 (the release predicates whose evidence
these surfaces summarise) · ADR 0041 (re-evaluation over stored findings) ·
#351 (only a finding about *this* artifact condemns it — same family, one
level up).

## What is true today

`scan_findings` is per-scan history. Every run writes its rows under a fresh
`scan_id` (`crates/hort-adapters-postgres/src/scan_findings_repository.rs:218`
and `crates/hort-app/src/use_cases/quarantine_use_case.rs:1357`, both
`Uuid::new_v4()`), and nothing removes the previous run's. That part is
correct and stays.

Three readers summarise **every** scan instead of the last one. None scopes
to a `scan_id`, none de-duplicates:

| Site | Query shape | Consequence |
|---|---|---|
| `crates/hort-adapters-postgres/src/curation_queue_repository.rs:208` | `COUNT(*)`, `MAX(severity)` over `WHERE sf.artifact_id = a.id` | the queue's `finding_count` / `max_severity` grow with the rescan count |
| `crates/hort-adapters-postgres/src/patch_candidate_repo.rs:86` | the same shape | same distortion, and this surface **orders by it** |
| `crates/hort-adapters-postgres/src/retention_scan_reader.rs:162` | `SELECT … WHERE artifact_id = $1 ORDER BY detected_at` — every row | `RetentionUseCase` (`crates/hort-app/src/use_cases/retention_use_case.rs:429`) evaluates its predicate over the **union of all scans** |

**Measured, on one artifact of the dogfood instance:** the same per-finding
count read 31, then 35 after a few rescans, with 427 rows in total — against
a latest scan that is the only one any verdict consults.

## Why this is a defect

**The system already decided which scan counts.** The verdict derivation
reads the last one and only the last one:
`rejected_reevaluation` resolves findings through
`scan_history::last_findings`, i.e. the newest `ScanCompleted` and its CAS
blob. These three projections contradict that.

**The retention reader is not cosmetic.** It checks *freshness* against the
newest `ScanCompleted` on the stream — correctly — and then evaluates over
all findings ever recorded. A security-driven predicate therefore acts on a
vulnerability a later scan no longer reports, on a surface that deletes.

## What to build

All three answer about **the artifact's last scan**. The table stays
append-only; only the reads change.

### The trap a naive fix walks into

**"The newest `scan_id` in `scan_findings`" is not the last scan.** A scan
that found nothing writes no row. An anchor derived from the table itself
therefore returns the previous, dirty run for an artifact that has since come
clean — the same defect, quieter.

The anchor has to come from the **scan's identity**, not from the presence of
finding rows. Two candidates exist in the tree — the `ScanCompleted` event on
the artifact's stream, and the `kind='scan'` job row — and choosing between
them is part of this unit. A SQL projection that reads the event stream is
not an option (ADR 0008); if the job row cannot carry the answer either, say
so in the report with what you found rather than reaching for the stream.

## Acceptance

1. An artifact with N scans whose **last** scan found one finding reports
   `finding_count = 1` in the curation queue, whatever N is.
2. `max_severity` is the highest severity **of the last scan**, not the
   highest the artifact has ever carried.
3. An artifact whose last scan found **nothing** reads as clean on all three
   surfaces although earlier scans left rows. This is the item that rules out
   a table-internal anchor — it cannot be satisfied by one.
4. The patch-candidate surface orders by the corrected severity.
5. `RetentionUseCase` evaluates its predicate over the last scan's findings. A
   finding a later scan no longer reports drives no retention decision.
6. The retention freshness gate is unchanged — it asks a different question
   (*is there a recent enough scan at all*) and is correct.
7. No row is deleted. This unit removes no history.
8. **Counter-assertion.** A test with two scans whose second reports a
   *proper subset* of the first pins that the answer is the subset and not the
   union — a `DISTINCT`-shaped fix would be green here and still wrong.
9. `hort-adapters-postgres` needs ≥ 85% and the DB-backed tests carry
   `#[serial(hort_pg_db)]`; `hort-app` needs 100% for any branch added there.

## Out of scope

- The verdict derivation. It already reads correctly and is not touched.
- The accumulation itself. Per-`scan_id` history is intended.
- Any cleanup or retention **of** `scan_findings` rows.
- The freshness gate.
