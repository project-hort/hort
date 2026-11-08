# 371 — A repeat catches up the missing gate

**Issue:** #404 · **Branch:** `agent/404-gate-aware-dedup` · single item.

Second of the two units from the #402 adversarial review's finding 1. #403
prevents new cases; this one heals the ones that exist. It does **not**
presuppose #403: it heals what arose before it too.

## What holds

An artifact whose gate commit never landed stays ungated forever — **even if
the same mount is repeated.**

`register_by_hash_inner`'s idempotence guard checks same path and same hash
(`crates/hort-app/src/use_cases/ingest_use_case.rs:4623-4641`) and returns
`RegisterOutcome::Duplicate { artifact: existing, … }` — **before** any policy
resolution and before the gate. The OCI handler maps that to `201 Created`.

So the `trigger_source` fix from #402 does not reach the rows that already
exist: a `skopeo copy` or a re-tag that somebody repeats today reports success
and changes nothing. Fifteen such artifacts were found in a live instance —
one `ArtifactIngested` each, `quarantine_status` `NULL`, in a repository with
`scan_backends = {trivy}` and `enforcement = reject`. That they carry scan
rows now is incidental: a `cronRescanTick` was enabled experimentally and
`select_eligible` caught them through `quarantine_status IS NULL`.

## The outcome, and the shape it now re-enters

**The dedup check becomes gate-aware:** a repeat that finds an artifact with
no gate result runs the gate instead of reporting `Duplicate`.

The same mount somebody repeats anyway then heals the row by itself, and no
sweep over existing installations is needed — a spread the maintainer
explicitly did not want (2026-11-02).

## What "no gate result" means is this unit's design question

It is to be decided with evidence, not guessed. What is known:

- **A cheap necessary condition is already in hand at the site.** `Duplicate`
  carries the whole `existing` artifact, so `existing.quarantine_status` costs
  nothing. A gate that ran with `quarantine_duration_secs > 0` leaves
  `Quarantined` / `Released` / `Rejected`; only the permissive case
  (`duration == 0`) stays `None` with the scan still requested. So
  `None` admits both the broken row and one healthy configuration, and
  anything more expensive runs only for rows that pass it.
- **The precise question is per axis**, because the gate itself is: a fully
  waived policy (`quarantineDuration: 0` AND `scanBackends: []` AND
  `provenanceMode: off`) legitimately produces **no** gate artifacts at all
  and the commit is skipped entirely. Such a row is correct and must keep
  answering `Duplicate`; a criterion that does not separate it from the
  broken row would re-gate healthy artifacts on every mount.
- **A constituent legitimately has no verdict of its own.** The code already
  carries that carve-out for the provenance axis —
  `is_parent_gated_blob_constituent`
  (`crates/hort-app/src/use_cases/referenced_descendant.rs:181`, used at
  `crates/hort-app/src/use_cases/quarantine_use_case.rs:2088`: *"a
  parent-gated blob is a STRUCTURAL hold (only the parent's cascade can lift
  it)"*). Whether the scan axis has an equivalent is to be **established, not
  assumed**; the reporter's count needed the `artifact_group_members`
  deduction (10 054 rows without an own `ScanRequested` against 15 genuinely
  broken), so the exception is real whatever its mechanism turns out to be.

Three traps, all measured, to respect in both the criterion and its tests:

1. **`events.stream_id` carries the `artifact-` prefix.** A join on the bare
   UUID matches **nothing** and returns a silent zero. A positive control on
   `ArtifactIngested` belongs in every such test.
2. **Without deducting constituents the count is three orders of magnitude
   off** (see above).
3. **"An artifact with no `kind='scan'` row" is not a usable criterion.** It
   found 281 hits in the live instance, all `rejected` — their job rows had
   been removed by the `scan-row-retention-sweep`. In an installation that
   prunes job rows, a missing row is no evidence. The missing **event** is.

## The catch-up is a follow-on append, so it is a PAIRED version read

The mint's own commit is a genesis append: the stream does not exist yet, so
there is no stored evidence to pair with, and
`read_unpaired_append_version(…, GenesisAppend)` is correct there.

**A catch-up is the opposite case.** The row and its stream already exist, and
the decision to run the gate is *derived from them* — "this artifact has no
gate result" is read before the append it protects. That is exactly the
condition the paired read exists for
(`crates/hort-app/src/use_cases/mod.rs`, `UnpairedAppend`'s docstring: *"The
moment a decision is derived from state read earlier — the artifact row, the
stream's own events, a findings blob — the version has to be read beside that
state, not after it"*). So the catch-up reads its version **with** the
evidence (`ArtifactAtVersion`), never through the unpaired helper.

That is also what makes concurrency safe without a lock: two simultaneous
repeats of the same mount both observe "no gate result", and the second
append fails the version check instead of landing a second
`ArtifactQuarantined` and a second scan row. A repeat is a retry by nature, so
losing that race is a correct outcome, not an error to paper over — but what
the caller then answers must be deliberate and stated.

## Acceptance

1. **The proof comes first.** A DB-backed test that starts from a gate-less
   genesis row and shows that a repeat answers `201` today without adding a
   scan row. Red before the change.
2. After the change the same repeat runs the gate: the scan row and
   `ScanRequested` are present, and the quarantine state is the one the gate
   determines.
3. **A concurrent double repeat lands one gate, not two.** Two catch-ups
   racing on the same artifact must not produce two `ArtifactQuarantined`
   events, two scan rows or two `ScanRequested`s. State what the loser
   answers.
4. **Idempotence survives for the healthy case.** A repeat on an artifact that
   has its gate result still answers `Duplicate` and creates **no** second
   scan row, no second `ArtifactIngested`, no second `ScanRequested`. This is
   the test that keeps this unit from building an idempotence defect. Cover
   the fully waived policy explicitly — it is the healthy row that looks most
   like the broken one.
5. The criterion for "no gate result" is justified in the code, with the
   constituent exception and the `artifact-` prefix named as traps.
6. Every DB-backed test carries `#[serial(hort_pg_db)]`.
7. `CHANGELOG.md`: one entry — a repeat catches up the missing scan instead of
   reporting success, and it names the operator action (repeat the mount).

## Not in this unit

- **A backfill sweep.** Deferred by the maintainer on 2026-11-02. This unit
  makes it largely unnecessary, because the healing rides the path that is
  repeated anyway.
- The atomicity of the two commits — **landed** (`46a2c4e0`). This unit must
  not re-open it: `register_by_hash_inner` now has exactly one
  `commit_transition_with_enqueues` (`:5158`), and the gate a repeat runs is
  that one call. A repeat that re-enters the gate must therefore commit the
  catch-up as one transition too, not as a second commit beside the existing
  row.
