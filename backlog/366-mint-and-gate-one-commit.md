# 366 — Mint and gate land together, or not at all

**Issue:** #403 · **Branch:** `agent/403-mint-and-gate-one-commit` · single item.

First of two units from the #402 adversarial review's finding 1. This one
makes new occurrences impossible; the second heals the rows that already
exist.

## What holds today

`register_by_hash_inner` (`crates/hort-app/src/use_cases/ingest_use_case.rs:4554`)
commits **twice**:

| Commit | What it carries | Site |
|---|---|---|
| Mint | the artifact row with `quarantine_status: QuarantineStatus::None`, `ArtifactIngested`, the `primary_content` edge | `:4873` |
| Gate | `ArtifactQuarantined` + `ScanRequested` + the `Scan` / `ProvenanceVerify` enqueues | `:5158` |

Between them sits
`read_unpaired_append_version(…, UnpairedAppend::SameCallFollowUp)` (`:5145`),
and both error paths propagate with `?`.

**After the first commit the artifact is servable.** `QuarantineStatus::None`
is the most permissive state in the system — `Artifact::is_downloadable`
admits it and the default `ReleasedOnly` index mode serves it. If the second
commit fails for any reason, exactly that is left behind: a servable artifact
that is never scanned, with a single `ArtifactIngested` in its stream and no
job row to make anyone aware it is owed a verdict.

This is measured, not theoretical: a fixture reproduced it
(`target_artifacts=1  jobs=0  events=1`), and a live instance was found
holding **15** such artifacts — hosted repository, `scan_backends = {trivy}`,
`enforcement = reject`, one `ArtifactIngested` each, `quarantine_status`
`NULL`.

## Why this is a deviation and not a design question

**The ordinary ingest path already does it right.** `ingest_inner`
(`:3745`) has exactly **one** `commit_transition_with_enqueues` (`:4130`) —
mint and gate in the same transaction. The call census in that file is
`:4130` (one), `:4873` + `:5158` (two).

**The primitive exists for this promise**, and its own docstring describes
this hazard verbatim for a different transition (`:3006-3012`):

> a scan/provenance-verify worker could pick up the just-enqueued job in the
> gap between the two commits and observe an anchor-less, `None`-status
> artifact that was actually seconds away from being quarantined — the
> no-strand crash-gap guarantee `commit_transition_with_enqueues` gives the
> enqueues now also covers this transition, since it rides the same append.

**And the code invokes a standing decision at the very site** (`:4970`): the
gate's parts land *"ATOMICALLY, in ONE follow-on commit
(`commit_transition_with_enqueues`, ADR 0002/0004 no-strand — mirrors
`ingest_inner`'s own guarantee that a quarantine transition and its
scan/provenance enqueue can never land separately)"*.

That is where the reasoning slips. The second commit is atomic **with
itself** — quarantine, `ScanRequested` and the enqueues never land
separately, and that part holds. What it is not is atomic **with the mint**.
The quoted no-strand promise covers "a quarantine and its enqueue"; it does
not cover "mint and gate", and that is the gap.

## The outcome

**`register_by_hash_inner` commits once, like `ingest_inner`.** No new ADR:
this restores conformity with ADR 0002/0004 rather than changing a decision.
No new state, no "quarantined until the gate runs", nothing to tune. The
dangerous remainder becomes impossible rather than repairable.

The shape is the gate computation moved **above** the single commit, its
events appended to the same `events` vec, and its enqueues and the mint's
`edges` passed to the same call — which is what `:4130` already looks like.

**To establish first, and it is the one open question:** does anything in the
gate computation need the **already committed** row? What is readable from
the code:

- policy resolution takes only `repository_id`
  (`resolve_active_policy_for_repo`, `:5004`), and the gate flags derive from
  the projection alone (`:5018-5034`);
- the quarantine decision mutates `artifact` in memory, and the merged commit
  would persist the mutated value — the `ingest_inner` shape;
- `read_unpaired_append_version(…, SameCallFollowUp)` reads the version
  *after* the first append; in the merged shape there is no first append to
  read after, so the call disappears rather than needing an answer;
- the descendant carve-out and the content-age probe (`:5050-5062`) read by
  content hash and by target hash. Merged, they run before this
  registration's own row and edge exist — which is exactly the position
  `ingest_inner` evaluates them from, and what the comment at `:5042`
  already claims is the case here.

Note while reordering: that comment, and the one at `:5175`, both describe
the `primary_content` edge as written *after* the mint. On this path the edge
rides the mint commit itself (`&edges` at `:4873`). It is harmless either way
— `PARENT_GATE_BLOB_KINDS` is `["oci_config", "oci_layer"]`
(`crates/hort-app/src/use_cases/referenced_descendant.rs:138`), so a
`primary_content` edge can never satisfy the descendant predicate — but both
comments describe an order that does not exist and should end up true.

**If merging turns out to break a real dependency, report it instead of
working around it.** Then the decision is taken again, and a hold state
before the gate is the alternative.

## Acceptance

1. **A test aimed at the class, not at the cause.** It forces the
   gate-bearing commit to fail by a route other than the `trigger_source`
   CHECK (which #402 fixed) and shows that **nothing servable** is left
   behind. The discriminator is the commit's *content*, not its ordinal — a
   double that fails "the second call" proves nothing once there is only one
   call, whereas one that fails "the commit carrying the quarantine
   transition or a non-empty enqueue list" is red before the change and green
   after. `MockArtifactLifecycle`
   (`crates/hort-app/src/use_cases/test_support.rs:2787`, the port impl at
   `:3273`) is the available seam, and the test is DB-free.
2. After the change `register_by_hash_inner` contains **one**
   `commit_transition_with_enqueues` call; a test or guard holds that, so the
   split cannot return.
3. The success path is unchanged: the mount answers `201`, the scan row and
   `ScanRequested` are present, the `primary_content` edge is present.
4. The #402 tests stay green, `oci_cross_mount_scan_enqueue_real_db` in
   particular.
5. Every DB-backed test carries `#[serial(hort_pg_db)]`.
6. `CHANGELOG.md`: one entry — a failed mount no longer leaves an unscanned,
   servable artifact behind.

## Not in this unit

- **The rows that already exist.** This unit prevents new ones; it heals no
  old ones. That is the second unit.
- The gate-aware duplicate-registration check.
- The `trigger_source` fix itself — that is #402.
