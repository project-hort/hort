# #108 backlog — release-gate verdict commit clobbers `quarantine_status`

Feature branch: `agent/108-verdict-commit-clobber`. Design doc:
`docs/plans/108-verdict-commit-clobber.md` (branch-local, D7). Dependency order:
1 → 2 → 4; 3 independent of 1/2 but same defect; 4 depends on 1+2+3.

## Item 1 — Verdict commits fail-closed under a concurrent status change (H2)

**Design doc section:** §2 D1
**Read first:** `crates/hort-app/src/use_cases/provenance_orchestration.rs` (load `:242`, late version read `:1449`, `apply_verdict` `:1304`, commit `:1459`), `crates/hort-app/src/use_cases/quarantine_use_case.rs` (`record_scan_result` `:359`, version read `:425`, reject batch `:722-740`), `crates/hort-app/src/use_cases/policy_use_case.rs:2021-2037` (the early-read pattern to mirror), `crates/hort-adapters-postgres/src/artifact_repo.rs:840-883` (`save_verdict_status_in_tx`), `crates/hort-adapters-postgres/src/artifact_lifecycle.rs` (`:132`, `:249-268`), `crates/hort-domain/src/ports/artifact_lifecycle.rs:208`, `crates/hort-app/src/use_cases/test_support.rs:2332` (`merge_verdict_status`), the two #90 tests (`provenance_orchestration_tests.rs:1026`, `quarantine_use_case.rs:2071`)
**Acceptance:**
- Both verdict paths read `expected_version` immediately after the artifact load
  (mirror `policy_use_case.rs:2021-2037`; warn + abort-this-artifact on read error).
- The status column is NOT written when the domain transition left it unchanged
  (the `Verified` case).
- `save_verdict_status_in_tx` gains a prior-status predicate (`WHERE id=$ AND
  quarantine_status IS NOT DISTINCT FROM $prior`); `rows_affected()==0` on a *present*
  row → new `DomainError::Conflict`; a truly-absent id still → `NotFound`. Prior status
  threaded through the `ArtifactLifecyclePort` methods.
- The two #90 regression tests flip to assert the concurrently-written `Rejected`
  survives (keeping their anchor-survival assertion); `MockArtifactLifecycle::merge_verdict_status`
  matches the conditional/skip-unchanged semantics.
- `hort-app` 100% + `hort-adapters-postgres` ≥85% on touched code (DB tests
  `#[serial(hort_pg_db)]`); no new metric names; full pre-push gate green.

### Starter prompt

/hort-architect

Implement Item 1 of `docs/plans/108-verdict-commit-clobber-backlog.md` (branch
`agent/108-verdict-commit-clobber`, issue #108 — HIGH). Read design doc §2 D1 and the
files above first. Close the H2 stale-snapshot clobber on BOTH verdict paths: (a) move
the `expected_version` read to just after the artifact load (mirror
policy_use_case.rs:2021-2037), (b) skip the status-column write when the transition
left status unchanged, (c) make `save_verdict_status_in_tx` conditional on the prior
status with a `Conflict`/`NotFound` split, threading prior status through the port.
Flip the two #90 regression tests (they currently assert the clobber wins) and update
`MockArtifactLifecycle::merge_verdict_status`. DB tests carry `#[serial(hort_pg_db)]`.
Run the full pre-push gate.

## Item 2 — Cascade commit uses the column-scoped verdict write (H2c)

**Design doc section:** §2 D2 — depends on Item 1
**Read first:** `crates/hort-app/src/use_cases/provenance_orchestration.rs:1095-1197`
(`cascade_one` version-read/retry `:1129-1158`, `commit_cascade_event` `:1176-1197`),
`crates/hort-adapters-postgres/src/artifact_lifecycle.rs` (`commit_transition` vs the
Item-1 verdict-scoped write), `crates/hort-domain/src/entities/artifact.rs` (`cascade_provenance_clearance` — leaves status unchanged)
**Acceptance:**
- `commit_cascade_event` routes through Item 1's verdict-scoped conditional write
  instead of `commit_transition`/`save_in_tx`; because `ProvenanceVerified` via cascade
  leaves status unchanged, no status-column write occurs (skip-unchanged) — the full-row
  clobber vector is gone.
- The cascade's existing read-version + retry-once OCC (`cascade_one`) is preserved
  unchanged; the three existing cascade-conflict tests (`provenance_orchestration_tests.rs:4084/4128/4168`)
  stay green.
- `hort-app` 100% on touched code; full pre-push gate green.

### Starter prompt

/hort-architect

Implement Item 2 of `docs/plans/108-verdict-commit-clobber-backlog.md` (branch
`agent/108-verdict-commit-clobber`, issue #108 — HIGH; depends on Item 1). Read design
doc §2 D2 first. Narrow `commit_cascade_event` from the full-row `commit_transition`
write to Item 1's column-scoped verdict write, preserving `cascade_one`'s existing
version-read/retry-once OCC and keeping the three cascade-conflict tests green. Run the
full pre-push gate.

## Item 3 — Release authority derives from the verdict, not event presence (H3 + ADR 0007 clarification)

**Design doc section:** §2 D3
**Read first:** `crates/hort-app/src/use_cases/quarantine_use_case.rs:1110-1147`
(`resolve_release_authority`, the presence-only check + its rationale comment),
`crates/hort-domain/src/events/artifact_events.rs:244-286` (`ScanCompleted.finding_count`
+ `validate`), the reject batch `quarantine_use_case.rs:722-740`,
`docs/adr/0007-fail-closed-quarantine-release-predicate.md` (release-authority section)
**Acceptance:**
- `resolve_release_authority` returns `ScanSucceeded` only when the **latest**
  `ScanCompleted` on the stream has `finding_count == 0` AND no later `ArtifactRejected`
  exists on the stream; a dirty-verdict `ScanCompleted` no longer authorizes release.
  The other four authorities unchanged.
- ADR 0007's release-authority section gains a one-paragraph clarification defining a
  "successful `ScanCompleted`" (latest-clean, no later rejection) — cite the human's
  refined→ready confirmation in the commit body.
- `hort-app` 100% on the authority matrix (design §4); the rationale comment at
  `:1110-1114` corrected; full pre-push gate green.

### Starter prompt

/hort-architect

Implement Item 3 of `docs/plans/108-verdict-commit-clobber-backlog.md` (branch
`agent/108-verdict-commit-clobber`, issue #108 — HIGH). Read design doc §2 D3 first.
Change `resolve_release_authority` to derive `ScanSucceeded` from the latest
`ScanCompleted`'s `finding_count == 0` AND absence of a later `ArtifactRejected`, not
mere event presence; correct the misleading rationale comment. Add the ADR 0007
clarifying paragraph (successful = latest-clean-no-later-reject). Cover the full
authority matrix. Run the full pre-push gate.

## Item 4 — True concurrency regression pin (interleave proof)

**Design doc section:** §2 D4 — depends on Items 1+2+3
**Read first:** the two #90 tests (now flipped by Item 1) as the anti-pattern
(`ExpectedVersion::Any`, wrong assertion), `crates/hort-app/src/use_cases/test_support.rs`
(mock lifecycle + event store for interleaving), `provenance_orchestration_tests.rs`
harness
**Acceptance:**
- An app-layer interleave test commits `ArtifactRejected` during the provenance verify
  window and asserts (a) final `quarantine_status == Rejected`, (b) the artifact is NOT
  timer-releasable afterward (`resolve_release_authority` denies) — the composed D1–D3
  proof.
- Distinct from the flipped #90 unit tests: this one exercises the real OCC path (early
  version read + append conflict), not `ExpectedVersion::Any`.
- `hort-app` coverage holds at 100%; full pre-push gate green.

### Starter prompt

/hort-architect

Implement Item 4 of `docs/plans/108-verdict-commit-clobber-backlog.md` (branch
`agent/108-verdict-commit-clobber`, issue #108 — HIGH; depends on Items 1–3). Read
design doc §2 D4 first. Add the app-layer interleave regression pin: commit
ArtifactRejected inside the provenance verify window, assert final status stays Rejected
and the artifact is not timer-releasable. Exercise the real early-version-read OCC path
(not ExpectedVersion::Any). If the pin fails, STOP and report — do not weaken it. Run
the full pre-push gate.

## Sequencing / notes
- Merge order on the branch: 1 → 2 → 3 → 4 (4 is the acceptance proof; 3 can land
  anytime but its ADR touch benefits from human confirmation first).
- Collision watch: #115 Item 3 also edits `provenance_orchestration.rs` +
  `artifact.rs` (the verdict *arms*; #108 edits the *commit* path + authority). Whichever
  merges to develop second rebases; no logical conflict expected.
- No new port beyond the prior-status parameter; no `AppContext` field; no adapter
  import in a format crate. One conditional-UPDATE shape change, no migration.
