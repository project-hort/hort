# 401 — A reached verdict supersedes an absent one

**Issue:** #419 · **Branch:** `agent/419-a-verdict-supersedes-an-absent-one` ·
single item. **One ADR amendment plus a domain, application and adapter
change.** No new CLI verb, no new endpoint, no new release authority.

**Governing decisions.** ADR 0007 (*Fail-closed quarantine release predicate*)
— amended by this item; its retry-exhaustion split already gives the
`quarantined` branch self-healing and this extends the same property to the
other branch. ADR 0065 D2 (*an irreversible operation acts only on positive
evidence; absent or ambiguous evidence means do not act*) and D4 (*where both
directions look restrictive, recoverability decides*) — both name ADR 0007 as
a source, so the inconsistency sits inside their own origin. ADR 0062
(closure) and ADR 0055 (write-authorized hold reads) are **untouched**;
neither needs an edit. **ADR 0064 needs no edit either** — its statement that
the periodic rescan does not revisit a terminal row is explicitly about
`Rejected`, and `Rejected` stays terminal here. Do not amend 0062, 0055 or
0064.

## The property

**An artifact held because no scanner reached a verdict accepts a later
verdict that is reached.** A blocking one condemns it; a non-blocking one
returns it to the hold, and the ordinary release sweep decides from there. The
state stops being a dead end whose only exit is a curator override.

## What is wrong today

`QuarantineStatus::ScanIndeterminate` accepts **no** new scan verdict of
either sign. In `crates/hort-domain/src/entities/quarantine_transitions.rs`:

- `RecordCleanScan` → `Released | Rejected | ScanIndeterminate => Forbidden`
- `RejectFromScan` → `Rejected | ScanIndeterminate => Forbidden`
- `ReEvaluate` → `NoneSt | Quarantined | Released | ScanIndeterminate => Forbidden`
- `Release` → `ScanIndeterminate => Allowed(&[Released])` — the only exit, and
  it is `hort-cli curation waive`.

Three consequences, all observed on registry.hort.rs on 2026-11-06/07:

1. **No self-healing.** 21 `hort-base/postgres` artifacts sit terminal from
   `trivy=no_analyzer_matched` on layer blobs — an abstention about hort's own
   materialisation, not about the bytes. ADR 0062's closure then withholds
   every manifest binding them.
2. **`hort-cli admin rescan` is a silent no-op.**
   `crates/hort-app/src/use_cases/manual_rescan_use_case.rs` has **no**
   quarantine-status precondition — it checks only for an in-flight job — so
   the job is enqueued and runs, and only the landing fails:
   `Artifact::record_clean_scan` (`entities/artifact.rs:985`) returns
   `DomainError::Invariant`. The operator gets a `task_job_id` and nothing
   changes. `crates/hort-http-oci/src/error.rs` already documents the exit as
   "admin override **or a successful rescan**" — the second half is not
   reachable today.
3. **The waive records something untrue.** `ArtifactReleased { authority:
   CuratorWaiver }` asserts that a curator decided this artifact's case. For
   an artifact nobody could assess, nobody did; the rule changed.

The terminality was never decided. ADR 0007's branch reads "→ terminal
`scan_indeterminate`, *exactly as before this amendment*", and the one place
that ADR argues **about** the state concludes it is **not** the graver one:
*"`ScanIndeterminate` means no verdict was reached, while a waivable
`Quarantined` artifact may carry findings a policy weighed and permitted."*

## Part 1 — the ADR amendment

Append to `docs/adr/0007-fail-closed-quarantine-release-predicate.md` under
*Decision*, in the style of the amendments already there. Text to land
verbatim (adjust only if the code ends up contradicting it, and then say so):

> ### A reached verdict supersedes an absent one: `scan_indeterminate` is a hold (issue #419, amended 2026-11-07)
>
> The retry-exhaustion split above gave the `quarantined` branch self-healing
> — re-scanned once the scanner recovers, *"self-healing without operator
> intervention"* — and left the other branch terminal. That terminality was
> carried, not decided: the branch reads *"exactly as before this amendment"*,
> and the only place this ADR argues about `scan_indeterminate` concludes it
> is **not** the graver state. This amendment extends the same property to it.
>
> 1. **A new scan verdict is admissible from `scan_indeterminate`.** A
>    `ScanCompleted` whose policy verdict blocks condemns exactly as it does
>    from `quarantined`. A `ScanCompleted` whose verdict does not block
>    returns the artifact to **`quarantined`** — never directly to
>    `released`. The release decision is then the ordinary one, under the
>    live gate, with the authority enumeration above applying unchanged.
>    This mirrors `RepairProvenanceMisrejection`, whose rule is that a
>    repair returns the artifact to the hold and lets the sweep make the
>    release decision.
> 2. **The stranded-rescan selector reaches it.** `scan_indeterminate` stops
>    being excluded from `select_stranded`; `rejected` and deleted rows stay
>    excluded. A state nothing re-picks is terminal in practice whatever the
>    transition table says, so the two halves are one decision and not a
>    follow-on.
> 3. **`rejected` is untouched.** A positive disproof is a statement about the
>    artifact and stays terminal; an absent verdict is a statement about
>    hort's own coverage and does not.
>
> **Why this is still fail-closed.** The two impossible failure modes in
> *Context* are unchanged. The artifact returns to a **hold**, never to
> `released`: release still requires one of the enumerated authorities, and a
> `ScanCompleted` on the stream is what authority 1 reads. No authority is
> added and no release path changes. What changes is that the stricter of two
> restrictive outcomes stops being the one an *absence* produces — ADR 0065
> D2 and D4, both of which name this ADR as a source.
>
> **A state entered only from `None` or `quarantined`**
> (`FailScanIndeterminate`) never conceals an earlier rejection, so no later
> verdict can silently undo one. That is the one argument terminality would
> have had, and it does not apply.
>
> **Scope.** Read visibility is a different axis and is untouched: ADR 0055's
> write-authorized hold-read exemption still does not extend to
> `scan_indeterminate`, and a held artifact stays unresolvable for every
> caller including its publisher. ADR 0062's closure is unchanged — a
> constituent that leaves the state simply becomes deliverable again.
> Re-assessment stays bounded by the scan job's existing attempt budget and
> backoff: a deterministic abstention answers the same way every time and must
> not become a hot loop.

## Part 2 — the transition

`crates/hort-domain/src/entities/quarantine_transitions.rs`:

- **Blocking verdict:** `RejectFromScan` gains
  `ScanIndeterminate => Allowed(&[Rejected])`. `Rejected => Forbidden` stays.
- **Non-blocking verdict:** the artifact must move `ScanIndeterminate →
  Quarantined`. **Do not widen `RecordCleanScan` for this.** That event is
  documented as the guard for a scan observation that *does not transition*
  the artifact (`entities/artifact.rs:960-984`), and this one does; a second
  meaning on one event is how a reader stops being able to tell which. Add a
  distinct event whose arm is `ScanIndeterminate => Allowed(&[Quarantined])`
  and `Forbidden` everywhere else, mirroring `RepairProvenanceMisrejection`'s
  shape — single source state, single target, the hold rather than the
  release. Name it for what it is (a reached verdict superseding an absent
  one), not for the state it leaves.
- The entry arm `FailScanIndeterminate` is unchanged, and so is `ReEvaluate`
  (see *Out of scope*).

`crates/hort-domain/src/entities/artifact.rs`: the paired method beside
`record_clean_scan` (985) and `reject_from_scan` (1055), with the same
shape — read the transition table, map `None` to a `DomainError::Invariant`
naming the state.

## Part 3 — the application path

`crates/hort-app/src/use_cases/quarantine_use_case.rs::record_scan_result`
(1191) must take the new transition when the artifact it loads is in
`ScanIndeterminate`, rather than failing the guard. A blocking verdict goes
the existing `reject_from_scan` way. Nothing else about the method changes:
same event, same commit shape, same pairing.

`record_scan_indeterminate` (2370) is untouched — a *repeated* absence from an
already-indeterminate artifact stays the existing idempotent skip.

## Part 4 — the sweep

`crates/hort-adapters-postgres/src/rescan_candidates.rs::select_stranded`
(188) selects `quarantine_status = 'quarantined'`. Widen it to
`IN ('quarantined','scan_indeterminate')` and rewrite the comment at 228-238,
which currently states the exclusion as settled by ADR 0007. `rejected` and
soft-deleted rows stay excluded; the in-flight-job exclusion and the
scan-policy guard are unchanged.

Note for the reviewer: `live_reads_exclude_deleted` governs this statement —
keep its `deleted_at IS NULL` intact.

## Part 5 — the paperwork

- `crates/hort-http-oci/src/error.rs`: the `ScanIndeterminate` doc comment
  says the exit is "admin override or a successful rescan". After this change
  both halves are true. **Verify it reads correctly rather than leaving it
  untouched by default.**
- `docs/architecture/**`: any page describing the quarantine state machine or
  the scan pipeline. Grep for `scan_indeterminate`; a page that calls it
  terminal needs the same correction.
- `docs/glossary.md` if it defines the state.
- `CHANGELOG.md` under `[Unreleased]`: one or two lines, operator-facing —
  what changed and what an operator no longer has to do. No mechanism.

## Tests

- Transition table: the new arm, and that every other source state stays
  `Forbidden` for it. The table's tests are exhaustive over `QuarantineStatus`
  — keep them so.
- Domain: the new `Artifact` method accepts `ScanIndeterminate` and refuses
  the rest with the invariant message naming the state.
- Application: an artifact in `ScanIndeterminate` whose next scan yields a
  non-blocking verdict ends in `Quarantined`; one whose next scan blocks ends
  in `Rejected`. Use the `hort-app` use-case mocks
  (`crates/hort-app/src/use_cases/test_support.rs`), not the HTTP harness.
- Adapter, DB-backed: `select_stranded` returns a `scan_indeterminate` row and
  still does **not** return a `rejected` one or a soft-deleted one. Carries
  `#[serial(hort_pg_db)]` like every DB-backed test in the workspace.
- No release-predicate test changes: the authority enumeration is unchanged,
  and that it is unchanged is itself worth asserting if a cheap assertion
  exists.

## Acceptance

- An artifact in `scan_indeterminate` whose next scan reaches a verdict ends
  in `quarantined` (non-blocking) or `rejected` (blocking), and the ordinary
  release sweep decides from there.
- `hort-cli admin rescan` on such an artifact has a reachable effect.
- The stranded selector picks a `scan_indeterminate` row and still skips a
  `rejected` one — shown DB-backed.
- **Unattended healing, over the whole chain.** When the cause of the
  abstention goes away — the exemplar is a `ScanPolicy` moving to
  `compositeVerdictMode: promoted`, after which `NoAnalyzerMatched` no longer
  gates an `OciBlob` — the next sweep rescan returns
  `Completed { assessment: NotApplicable }`, that verdict lands, and the
  release sweep releases the artifact, because ADR 0007 states a
  `not_applicable` assessment *"satisfies authority 1 exactly as a clean
  verdict does"*. No `waive`, no operator step.
- No new release authority: ADR 0007's enumeration is unchanged.
- A deterministically abstaining artifact is retried at sweep cadence, not in
  a loop inside one tick.
- The change adds no uncovered lines (intersect the diff's added line numbers
  with `cargo llvm-cov --show-missing-lines`, per touched file).

## Out of scope

- **`Rejected` and its recovery path** (`curation reevaluate`). A positive
  disproof stays terminal.
- **`curation reevaluate` is not extended.** It reads the latest
  `ScanCompleted` and the latest `ArtifactRejected` and re-runs the active
  policy over them; a `scan_indeterminate` artifact has no `ScanCompleted`
  (`record_scan_indeterminate` appends `DomainEvent::ScanIndeterminate`), and
  the use case has a named outcome for that,
  `rejected_reevaluation::RejectedDerivation::NoScanCompleted`. Once this item
  lands, a rescan produces the `ScanCompleted` that reevaluate would need
  anyway, so nothing there has to change.
- **Read visibility of held content** (ADR 0055).
- **Recomputing a verdict without re-running the scanner.** That would need
  the abstention stored typed rather than as the `reason` string
  `DomainEvent::ScanIndeterminate` carries today. Separate decision, not a
  blocker for this one.
- **The 21 artifacts already held on registry.hort.rs.** They do not heal
  retroactively from this change alone; they heal on their next sweep rescan
  once both this item and the policy change are live.

## Gate

`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace` (once for the whole branch), `cargo-audit audit -D
warnings`, `cargo-deny check`, `bash scripts/run-shell-guards.sh`.
