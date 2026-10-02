# 257 — Project `fixed_versions` so `HasFixAvailable` can do what it says

**Issue:** #323 · **Branch:** `agent/323-fixed-versions-projection`
**Governing decisions:** ADR 0015 (a policy field accepted at apply must be
enforced at runtime or rejected at apply) · ADR 0030 (expand/contract) · the
human's decision of 2026-09-30, quoted below.

## Why

`PolicyPredicate::HasFixAvailable` matches when a finding carries a non-empty
`fixed_versions` (`crates/hort-domain/src/retention/evaluate.rs:194`). The
production adapter never populates that field: `scan_findings` (migration 009)
has no such column, so `PgRetentionScanReader` hands back `Finding` rows with
`fixed_versions` empty and the predicate can never match. The apply-time
linter accepts the predicate anyway. An operator writes a retention policy and
gets silence — the exact class ADR 0015 forbids.

ADR 0015 allows closing this by rejecting the predicate at apply. **That is
not the decision.** The human, 2026-09-30:

> *"Ok, aber wir haben noch keine finale Version 1.0. Dass ein Feature
> zwischenzeitlich beginnt, so zu funktionieren, wie es gedacht ist und nicht
> mehr, wie es beim ersten Versuch funktionierte, ist nicht unerwartet.
> Operator müssen aktuell damit umgehen können. Wir sollten das also richtig
> bauen."*

So: deliver the capability. The value is already in hand at the moment the row
is written — the scanner produces `Finding::fixed_versions`
(`crates/hort-adapters-scanner-osv/src/parse.rs:517`, capped at 32 entries),
and `build_scan_findings_rows` drops it on the floor while mapping to
`ScanFindingsRow`. The retention read already happens for every artifact that
passes the scope gate, unconditionally and before any security-predicate check
(`crates/hort-app/src/use_cases/retention_use_case.rs:428`), so carrying one
more column costs nothing at runtime.

Two consequences are accepted rather than solved, and both must be written
down where an operator will find them:

1. **Rows written before this change read as "no fix."** They get the column
   default. The predicate therefore under-matches for an artifact not rescanned
   since — the safe direction, fewer expiries rather than more — and the gap
   closes on its own as the cron-driven rescan reaches each artifact. No
   backfill.
2. **A policy that already names `HasFixAvailable` stops being inert.** It
   begins expiring artifacts with no operator action behind it. This is the
   change the human accepted above; it is not to be softened with a flag, a
   grace period, or an opt-in. It belongs in `CHANGELOG.md` stated plainly.

## What to do

### 1. Migration `029_scan_findings_fixed_versions.sql`

Add `fixed_versions text[] NOT NULL DEFAULT '{}'::text[]` to
`public.scan_findings`.

- This is **expand**, not contract: it removes and narrows nothing, so it takes
  **no** `migrations/CONTRACTIONS.toml` entry. Do not add one.
- `ADD COLUMN` with a non-volatile default is metadata-only from PG 11 on and
  the project floor is 16 — no table rewrite. Say so in the migration header.
- Every other text column in this table carries a structural bound
  (`octet_length(purl) <= 512`, `title <= 1024`). Mirror that discipline with a
  bound on the array: the producer already caps at 32 entries in Rust, and a
  constraint that is only enforced in Rust is the kind of invariant this
  repository puts in the schema. Choose the bound to match the producer and say
  in the header where the 32 comes from.
- Follow the header conventions of the neighbouring migrations: what the
  column is, why it exists, why it is safe on a populated table.

### 2. Carry the value through the write path

- `ScanFindingsRow` (`crates/hort-domain/src/ports/scan_findings_repository.rs:26`)
  gains `fixed_versions: Vec<String>`.
- `build_scan_findings_rows`
  (`crates/hort-app/src/use_cases/quarantine_use_case.rs:99`) copies it from
  the `Finding` it is already holding.
- `insert_findings_in_tx`
  (`crates/hort-adapters-postgres/src/scan_findings_repository.rs:59`) binds
  the new column.

### 3. Carry it through the read path

`crates/hort-adapters-postgres/src/retention_scan_reader.rs`: the new column
joins `FindingRow`, the `SELECT`, and `into_domain`.

### 4. Correct every doc comment that asserts the gap

Four places currently state that `HasFixAvailable` can never match. All four
become false with this change and all four must be corrected — to what is now
true, including that `references` and `aliases` are still **not** projected:

- `crates/hort-domain/src/ports/retention_scan_reader.rs` — the *Precision
  note* section and the `list_findings_for_artifact` doc.
- `crates/hort-adapters-postgres/src/retention_scan_reader.rs` — the module
  doc's *`fixed_versions` not projected* section.
- `crates/hort-domain/src/retention/evaluate.rs` — the *`HasFixAvailable`
  precision note*.
- `crates/hort-app/src/use_cases/retention_use_case.rs:65` — the named
  follow-on line.

Grep for the claim rather than trusting this list; a fifth copy is likelier
than not.

### 5. The test that would have caught this

The existing predicate tests feed `fixed_versions` in directly, which is why
they never noticed the adapter. Add a DB-backed round trip in
`hort-adapters-postgres`: write a finding carrying a non-empty
`fixed_versions` through the **production** write path, read it back through
`RetentionScanReader`, assert the value survives — and assert the empty case
still reads back empty. `#[serial(hort_pg_db)]`, no exceptions.

### 6. `CHANGELOG.md`

An entry under `[Unreleased]`. This is a behaviour change an operator must be
told about: a retention policy using `HasFixAvailable` did nothing before and
expires artifacts now. Say that, and say that findings recorded before the
change read as "no fix" until their artifact is rescanned. Issue references
are the changelog's own convention and belong here — unlike in code comments.

## Explicitly out of scope

- **No backfill** of historical `scan_findings` rows from the CAS blobs.
- **No apply-time rejection** of the predicate. That was the alternative and it
  was not chosen; the capability replaces it.
- **No blob reading** in the retention evaluator, and no `StoragePort`
  dependency added to it.
- **No change** to `references` / `aliases` — they stay unprojected.
- **No change** to the reader returning rows across all of an artifact's scans.
  That is the documented port contract, and the predicate meaning "seen by some
  scan" rather than "true right now" is a property of the whole
  security-predicate family, not something to fix here.
- No new knob, no grace period, no opt-in gate on the activation.

## Acceptance

- A finding written through the production scan path with a non-empty
  `fixed_versions` is readable through `RetentionScanReader` with that value
  intact, proven by a DB-backed test.
- `HasFixAvailable` matches such a finding end to end.
- No doc comment anywhere still claims the predicate cannot match.
- `migrations/CONTRACTIONS.toml` is unchanged.
- `CHANGELOG.md` names the activation and the pre-change rows.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo-audit audit
  -D warnings`, `cargo-deny check`.
