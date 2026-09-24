# 223 — A purge must retire its projection, or it leaves the artifact broken

**Issue:** #286 · **Branch:** `agent/286-purge-retires-projection`
**Governing decisions:** the retention concept — this unit comes before every
other retention unit, **except that the candidate reader's `deleted_at IS NULL`
exclusion must land first or here**: retiring rows while the reader still ignores
retirement lets a second policy enumerate the retired row and append a fresh
`ArtifactExpired` after the terminal `ArtifactPurged`, which breaks the
terminal-tail assumption the eventstore sealing relies on · ADR 0054 (CAS-shared bytes) · ADR 0007 (invariant 1 is
untouched here).

## Why

`purge_artifact_refs` deletes the artifact's `content_references` and commits;
the use case then deletes the blob when the refcount reached zero and appends a
terminal `ArtifactPurged`. **There is no `UPDATE artifacts`.** The adapter
comment claims otherwise — *"Purge tombstones the `artifacts` row"*
(`crates/hort-adapters-postgres/src/purge_gc.rs:248-252`) — but it means the
event; `deleted_at` is written only by the user-facing delete path
(`crates/hort-adapters-postgres/src/artifact_repo.rs:303-325`).

Three consequences, all verified:

1. **Refcount > 0:** the blob correctly survives for the other referent, but the
   artifact recorded as `ArtifactPurged` **keeps serving** — `is_downloadable()`
   reads `deleted_at` and the status, and neither changed.
2. **Refcount 0:** the artifact is permanently broken. The row lives, the bytes
   are gone; a manifest `HEAD` answers 200 from the row while `GET` fails on the
   storage read.
3. **A re-push does not heal it.** Path and checksum are unchanged, and the
   ingest dedup keys on exactly that pair, breaking out **before** `storage.put`.

Until this is fixed, a working retention policy produces broken artifacts rather
than reclaimed space — which is why it precedes the rest.

## The schema already anticipates the fix

`migrations/021_artifacts_soft_delete.sql:44-49` replaced path uniqueness with a
**partial** unique index over live rows only (`WHERE deleted_at IS NULL`). A
retired row therefore frees its `(repository_id, path)` slot, a fresh ingest
creates a new row with a real CAS write, and the old row keeps its stream and
its `ArtifactPurged` as the audit identity.

## Read first

- `crates/hort-app/src/use_cases/purge_use_case.rs` — `process_one`,
  `finish_one_ref`, `append_purged`.
- `crates/hort-adapters-postgres/src/purge_gc.rs:220-350` — the transaction, the
  comment to correct, and the idempotent-retry recovery branch at lines 288-320
  with its recorded accepted-gap disposition.
- `crates/hort-adapters-postgres/src/refcount_reconcile.rs:150-235` — the scan
  that rebuilds missing `primary_content` / `metadata_blob` references.
- `crates/hort-domain/src/entities/artifact.rs:1594-1609` — `is_downloadable` /
  `is_promotable`, both keyed on `deleted_at`.
- `migrations/021_artifacts_soft_delete.sql`.

## Scope

1. **Retire the projection as part of the purge.** Set `deleted_at` in the same
   retry-safe transition that writes `ArtifactPurged` — not by calling the
   user-facing delete verb, so no second terminal event appears and the
   attribution stays with the retention actor. **Regardless of `refs_remaining`:**
   an expired artifact is retired even when its blob survives for another
   referent.
2. **Exclude retired rows from the refcount reconcile.** It scans `FROM artifacts a`
   with no `deleted_at` predicate (`refcount_reconcile.rs:157,200`) and recreates
   missing references, so it would treat the just-removed references as drift and
   put them back. Without this, step 1 is undone on the next sweep.
3. **Correct the false comment** in `purge_gc.rs`; it describes behaviour that
   does not exist. The accepted-gap paragraph above the recovery branch goes with
   it — it documents a disposition item 6 reverses. Both are being edited anyway,
   so the replacement text states the invariant and drops the tracker numbers
   rather than carrying them forward.
4. **Pin the recovery path:** purge → re-push the same content to the same path →
   the fetch returns bytes. That test is the real proof of this unit.

5. **Complete the purge at the artifact level, not per hash.** One artifact can
   yield several distinct `PurgedRef` hashes (`purge_gc.rs:259-345`), and the use
   case appends `ArtifactPurged` **inside** the per-hash loop
   (`purge_use_case.rs:282-285,340-404`) while the pending query excludes the
   artifact after **any** such event (`purge_gc.rs:183-195`). So if hash A
   succeeds and hash B's storage delete fails, B is never retried — and the
   artifact is recorded as purged while part of its content survives. The terminal
   event and the retirement happen only once **every** referenced hash has
   completed; a partial run leaves the artifact pending and retryable. Retiring
   the row before a failed delete would be the same bug wearing the fix's clothes.

6. **Make the retry able to finish what it started.** The completion gate in
   item 5 is only enforceable if a retry can still see what remains — and today
   it cannot. `purge_artifact_refs` derives the hash set from
   `DELETE … RETURNING`; on a retry those rows are already gone, and the set is
   recovered from `artifacts.checksum_sha256` plus
   `artifact_metadata.metadata_blob` alone (`purge_gc.rs:288-320`). The
   `oci_index_member` / `oci_subject` / `oci_config` / `oci_layer` targets are
   unrecoverable — no column anywhere records what the deleted edges pointed at.
   So an artifact whose OCI child delete failed would stay pending forever and
   its child blobs would leak silently: the completion gate would convert a
   bounded reporting gap into a permanent stall. **Persist the per-artifact hash
   worklist in the same transaction that deletes the edges**, and drive both the
   retry and the completion gate from it.

   This deliberately reverses the accepted-gap disposition recorded in
   `purge_gc.rs:294-320` ("do not expand the schema for it"). That disposition
   was sound under its own premise: purge was per-hash, the artifact was never
   retired, and a skipped target only meant *this call's* `PurgedRef` output was
   incomplete while the refcount in the database was already correct. Items 1
   and 5 change the premise — completion now decides whether an artifact is
   retired and its stream sealed — so the rationale is re-validated here rather
   than inherited, and the re-validation is recorded with the change. Note also
   that the gap was scoped by *how rare* retries are; the stall is a correctness
   property and does not become acceptable at any frequency.

7. **Bind the terminal event and the retirement atomically.** `ArtifactPurged`
   and `deleted_at` become visible together or not at all. A crash between them
   leaves either a retired artifact with no terminal event — invisible to every
   reader and unexplained in its stream — or a sealed stream over a row that
   still serves. One transition, one commit, one retry path.

## Acceptance

- After a purge the row is retired: no live lookup finds it, `is_downloadable()`
  is false, and `HEAD` and `GET` agree.
- The same holds with `refs_remaining > 0` — shared bytes stay, the expired
  artifact stops serving.
- A fresh ingest of the same content at the same path creates a **new** row and
  actually writes the blob; the fetch then returns bytes.
- The refcount reconcile creates no references for retired rows; a test covers a
  reconcile pass after a purge.
- `ArtifactPurged` remains the terminal event, still attributed to the retention
  actor, with no second deletion event.
- A multi-hash artifact whose second storage delete fails is **not** retired and
  **not** recorded as purged; the next sweep retries it and completes. The test
  uses at least two hashes and an injected failure — a single-hash fixture would
  pass every other criterion here while leaving the defect in place.
- That retry completes **every** outstanding hash, not only the two the current
  recovery branch can reconstruct. The fixture gives the artifact at least one
  `oci_layer` or `oci_index_member` edge, fails that child's storage delete once,
  and asserts after the retry that the child blob is gone and the artifact is
  retired. Without the worklist this test hangs the artifact in `pending`
  forever, which is exactly the point of it.
- The terminal event and the retirement are never observable apart: a test that
  interrupts the transition finds neither, and a reader never sees one without
  the other.
- Invariant 1 is unchanged: the three evidence states are still filtered before
  purge and still refused there.
- DB-backed tests carry `#[serial(hort_pg_db)]`; gate green; no issue, MR or
  backlog numbers in code comments.

## Explicitly not in this item

No predicate changes, no change to candidate enumeration, no claim work, no
CronJob switches.
