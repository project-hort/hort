# #108 — Release-gate verdict commit clobbers `quarantine_status` from a stale snapshot

Issue: #108 (source: audit #106 findings H2 + H3, HIGH, adversarially verified; spec
approved by the human 2026-08-05). Feature branch: `agent/108-verdict-commit-clobber`.
Branch-lifetime planning doc (D7).

## §1 Scope, sweep, rationale re-validation

A signed image that also trips a scan policy (signed + high-severity CVE) resurrects
from `Rejected` to `Quarantined` and then timer-releases. Three composed defects, each
individually documented as "safe":

- **H2a — late version read.** `ProvenanceOrchestrationUseCase::verify_artifact` loads
  the artifact at `provenance_orchestration.rs:242` but reads `expected_version` at
  `:1449` — *after* the full bundle-fetch/verify round trip — so a scan verdict that
  committed `ArtifactRejected` during that window is already in the stream version; the
  provenance append does NOT conflict. `Artifact::complete_provenance(Verified)`
  (`artifact.rs:791-809`) leaves `quarantine_status` at the stale-loaded `Quarantined`,
  so the commit writes `Quarantined` back over `Rejected`.
- **H2b — id-only projection UPDATE.** `PgArtifactRepository::save_verdict_status_in_tx`
  (`artifact_repo.rs:852-871`) is `UPDATE artifacts SET quarantine_status=$1,
  updated_at=$2 WHERE id=$3` — no prior-status predicate; `rows_affected()==0` maps to
  `NotFound` only. Both lifecycle callers (`commit_scan_result_with_score`
  `:132`, `commit_provenance_verdict` `:261`) pass the in-memory snapshot status; the
  port signature (`ports/artifact_lifecycle.rs:208`) has no slot for a prior status.
- **H2c — cascade full-row write.** `commit_cascade_event`
  (`provenance_orchestration.rs:1176-1197`) commits via `commit_transition` →
  `save_in_tx` (full-row), the write shape #90 removed from the two verdict paths but
  left here. The cascade *does* have version OCC (`cascade_one` reads version + retries
  once, `:1129-1158`), so it is version-guarded but full-row — a strictly-worse
  clobber surface if its guard is ever defeated.
- **H3 — authority-from-presence (amplifier).** `resolve_release_authority`
  (`quarantine_use_case.rs:1123-1147`) returns `ScanSucceeded` on the mere presence of
  any `ScanCompleted` — but the rejecting scan branch ALSO emits `ScanCompleted`
  (`:722-740`), first in the batch, before `ArtifactRejected`. The `ScanCompleted`
  payload already carries a validated clean/dirty discriminator (`finding_count`,
  `artifact_events.rs:244-286`, `findings_blob.is_some() == finding_count>0`), and the
  gate simply does not read it. So once H2 reverts the status, `release_expired`
  timer-releases with no verdict re-derivation. `Artifact::release`
  (`artifact.rs:650-680`) *would* refuse a `Rejected` source — but H2 already erased
  the state that guard reads.

**The #90 regression tests codify the bug.** `provenance_orchestration_tests.rs:1026`
(`provenance_verdict_commit_does_not_clobber_concurrently_written_anchor`) and
`quarantine_use_case.rs:2071` (scan mirror) both commit with `ExpectedVersion::Any` and
assert **"the verdict's own status change must land"** — i.e. they assert status-clobber
is desired, protecting only `quarantine_window_start`. These tests MUST flip. The test
double mirrors the defect: `MockArtifactLifecycle::merge_verdict_status`
(`test_support.rs:2332-2340`) copies `quarantine_status` unconditionally — the fix lands
in the mock too or the new pins pass vacuously.

**Deferred-items sweep (Step 0, 2026-08-05).** ADR-0000 register carries no row for
this; it was filed new by the audit. No `docs/plans/` deferral applies. **Rationale
re-validation:** #90's fix rationale ("column-scoped write protects the anchor from a
stale snapshot") is **reversed-in-part here** — it hardened the OTHER columns of exactly
these two call sites and its tests assert the status write wins; #90 scoped the anchor
and overlooked that `quarantine_status` itself is the security-load-bearing column. The
"terminal scan failure emits `ScanIndeterminate` not `ScanCompleted`, so presence ==
success" rationale (`quarantine_use_case.rs:1110-1114`) is **reversed here**: it covers
scanner *execution* failure but conflates "the scanner ran" with "the artifact passed"
— a rejecting scan is a successful *execution* with a dirty *verdict*.

**Relationship to other in-flight branches.** #115 Item 3 (descendant provenance hold)
edits `complete_provenance`'s arms + `provenance_orchestration.rs` verdict apply; #108
edits the same file's *commit* path (version-read placement, cascade write shape) and
`resolve_release_authority`, not the verdict arms. Low collision but same two files —
whichever merges second rebases; noted in both backlogs. No interaction with #107/#109.

**Explicitly out of scope.** (i) Adding a dedicated `version`/`revision` OCC column to
`artifacts` — the early version read closes H2a at the event-store layer (both verdict
paths append to the same `StreamId::artifact(id)`), and `quarantine_status IS NOT
DISTINCT FROM $prior` gives the projection backstop with no migration; a new column is
unjustified surface. (ii) Reworking the scan path's own version-read timing beyond what
H2a needs (it reads at `:425`, earlier than provenance; the same early-read discipline
applies but the primary wide window is provenance's). (iii) `download_audit`/other
release surfaces — H3 is scoped to `resolve_release_authority`.

## §2 Decisions

### D1 — Verdict commits fail-closed under a concurrent status change (H2a+H2b)

Two-layer close on both verdict paths (provenance `verify_artifact`; scan
`record_scan_result`):

1. **Early version read (primary).** Read `expected_version` immediately after the
   artifact load, mirroring `policy_use_case.rs:2021-2037` verbatim in shape (warn +
   abort-this-artifact on read error). Because both verdict paths append to the same
   `StreamId::artifact(id)`, a concurrent verdict's append bumps the version and the
   later append fails `Conflict` — the paired projection write never runs.
2. **Skip-unchanged status write.** When the domain transition left
   `quarantine_status` equal to the loaded value (the `Verified` case — status stays
   `Quarantined`), do NOT write the status column at all. This removes the
   provenance-Verified revert vector *at the source*, independent of timing.
3. **Conditional projection UPDATE (backstop).** Thread the *prior* (loaded) status
   through the port; `save_verdict_status_in_tx` becomes `... WHERE id=$ AND
   quarantine_status IS NOT DISTINCT FROM $prior`; `rows_affected()==0` splits into a
   new `DomainError::Conflict` (distinct from the existing `NotFound` for a genuinely
   absent id). This is defense-in-depth behind layer 1 — the event-store OCC is the
   primary close; the conditional UPDATE catches any future path whose append does not
   conflict.

Flip the two #90 regression tests to assert the concurrently-written `Rejected`
**survives** (status-clobber is now the defect, not the contract), keeping their
anchor-survival assertion. Update `MockArtifactLifecycle::merge_verdict_status` to the
same conditional/skip-unchanged semantics so app-layer pins are real.

### D2 — Cascade commit uses the column-scoped verdict write (H2c)

Route `commit_cascade_event` through the same verdict-scoped conditional write as D1
instead of `commit_transition`/`save_in_tx`. The cascade's `ProvenanceVerified` leaves
status unchanged, so under D1's skip-unchanged rule it writes no status column at all —
the full-row clobber vector disappears while the cascade keeps its existing
read-version-and-retry-once OCC (`cascade_one`).

### D3 — Release authority derives from the verdict, not event presence (H3)

`resolve_release_authority` returns `ScanSucceeded` only when the artifact's **latest**
`ScanCompleted` on the stream carries `finding_count == 0` **and** no later
`ArtifactRejected` appears on the stream. A rejecting scan's `ScanCompleted`
(`finding_count > 0`, followed by `ArtifactRejected`) no longer counts as a release
authority. The other four authorities (`ScanWaived`, `AdminOverride`, `CuratorWaiver`,
`PolicyReEvaluation`) are unchanged. This is an ADR-0007-conformance fix — the ADR
already means "a *successful* ScanCompleted"; the code read "any."

**ADR scope (flag at the refined gate):** ADR 0007's release-authority section says
"a successful `ScanCompleted`" — ambiguous enough to have been misimplemented as
presence. Item 3 adds a one-paragraph clarification defining "successful" =
latest-`ScanCompleted`-clean-and-no-later-`ArtifactRejected`. Human confirmation of
refined→ready is taken as approval for exactly that clarification; splittable into an
`agent:decision` on request.

### D4 — True concurrency regression pin

An interleaving test (app-layer, `test_support` mocks) that commits `ArtifactRejected`
during the provenance verify window and asserts the final status is `Rejected` and the
artifact is NOT timer-releasable — the end-to-end proof the composed D1–D3 close the
defect. This is the pin the #90 tests should have been; it exercises the OCC dimension
those tests bypass with `ExpectedVersion::Any`.

## §3 Observability

No new metric names/labels. D1's new `Conflict` on the verdict UPDATE logs `warn!`
(concurrent-modification, recoverable — the losing verdict is re-derivable) at the
adapter layer, matching the existing `commit_transition` conflict convention. D3's
authority denial rides the existing `resolve_release_authority` decision logging.

## §4 Test plan / coverage

- `hort-app` 100% on touched branches: early-version-read abort arm (both paths),
  skip-unchanged vs. write-status arms, D3 authority matrix (latest-clean-no-reject →
  ScanSucceeded; latest-dirty → denied; clean-then-later-reject → denied; the other
  four authorities unchanged), D4 interleave pin, flipped #90 unit tests.
- `hort-adapters-postgres` ≥85%, **every new DB test `#[serial(hort_pg_db)]`**:
  conditional UPDATE matches on equal prior status; 0-rows→`Conflict` on changed prior
  status; `NotFound` still returned for a truly absent id (the split is correct).
- Mock `merge_verdict_status` parity test so the double cannot silently diverge from
  the adapter again.
- Full pre-push gate per CLAUDE.md.
