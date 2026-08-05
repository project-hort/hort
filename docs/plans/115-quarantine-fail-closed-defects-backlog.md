# #115 backlog — fail-closed quarantine defects (seed-import strand; zero-window descendant × Required)

Feature branch: `agent/115-quarantine-fail-closed-defects`. Design doc:
`docs/plans/115-quarantine-fail-closed-defects.md` (branch-local, D7). Items 1–3 are
independent of each other; Item 4 depends on Item 3. One directive = one item.

## Item 1 — Seed-import path enqueues scan + provenance atomically with the backdated quarantine

**Design doc section:** §2 D1
**Read first:** `crates/hort-app/src/use_cases/ingest_use_case.rs` (the
`quarantine_anchor_override` branch in `register_by_hash_inner` ~3766+; `ingest_inner`'s
`scan_will_run` / `provenance_will_run` gates ~2738+ and the
`commit_transition_with_enqueues` call ~2970+), `crates/hort-app/src/use_cases/seed_import_use_case.rs`
(module doc + `run_one`), `crates/hort-app/src/use_cases/test_support.rs`
**Acceptance:**
- The seed branch resolves the active policy (same resolution `ingest_inner` uses) and
  lands `ArtifactQuarantined` + gated `ScanRequested` + `IngestEnqueue::Scan` /
  `IngestEnqueue::ProvenanceVerify { trigger_source: "seed-import" }` in ONE
  `commit_transition_with_enqueues` transaction. Non-seed callers
  (`quarantine_anchor_override = None`) are bit-identical to today.
- `scan_backends: []` policies enqueue nothing (release via `ScanWaived` unchanged);
  provenance enqueued iff `mode ≠ Off` ∧ format ∈ `provenance_capable_formats`.
- `SeedImportUseCase` module doc corrected ("next sweep releases it on a clean scan"
  now true because the scan IS requested); the seed × `Required` immediate-rejection
  consequence documented per D1.
- `hort-app` 100% coverage on the touched paths (test matrix per design §4); no new
  metric names; workspace gate green.

### Starter prompt

/hort-architect

Implement Item 1 of `docs/plans/115-quarantine-fail-closed-defects-backlog.md` (branch
`agent/115-quarantine-fail-closed-defects`, issue #115 defect (a) prevention). Read
design doc §2 D1 and the files above first. In
`IngestUseCase::register_by_hash_inner`, make the `quarantine_anchor_override`
branch mirror `ingest_inner`'s atomic enqueue gate: resolve the active policy, compute
`scan_will_run`/`provenance_will_run` with the exact same derivations, and convert the
quarantine follow-on commit to `commit_transition_with_enqueues` carrying the gated
`ScanRequested` event + `Scan`/`ProvenanceVerify` enqueues
(`trigger_source: "seed-import"`). Do NOT touch the `None` callers (OCI mount /
pull-dedup follower — that is #107's scope). Restate acceptance criteria above in your
report; run the full pre-push gate.

## Item 2 — `select_stranded` recovers job-less quarantined artifacts (scan-policy-aware)

**Design doc section:** §2 D2
**Read first:** `crates/hort-adapters-postgres/src/rescan_candidates.rs`
(`select_eligible`'s policy LATERAL ~100-135, `select_stranded` ~175-230),
`crates/hort-adapters-postgres/tests/rescan_candidates.rs`, `migrations/005_policy.sql`
(`policy_projections.scan_backends`), ADR 0007 (rescue-path paragraph)
**Acceptance:**
- `select_stranded` selects `quarantined ∧ ¬deleted ∧ (most-recent scan job failed ∨
  NO scan job exists) ∧ no pending/running job ∧ resolved policy scans`
  (repo-scoped-else-global policy LATERAL as in `select_eligible`;
  `scan_backends` empty ⇒ excluded; no policy row ⇒ default-policy fallback ⇒
  included).
- DB-gated tests per design §4 — **every new DB test carries
  `#[serial(hort_pg_db)]`** (hard review block otherwise).
- The port-trait doc comment and the SQL comment block describe the widened
  predicate; terminal states (`rejected`, `scan_indeterminate`) remain never selected.
- Workspace gate green.

### Starter prompt

/hort-architect

Implement Item 2 of `docs/plans/115-quarantine-fail-closed-defects-backlog.md` (branch
`agent/115-quarantine-fail-closed-defects`, issue #115 defect (a) cure — this is the
ONLY remediation for already-stranded seed imports; no manual rescan surface exists).
Read design doc §2 D2 and the files above first. Widen
`RescanCandidatesRepository::select_stranded` per the acceptance criteria: LEFT JOIN
LATERAL on the most-recent scan job (`failed` OR absent), plus the
scan-policy-aware guard reusing `select_eligible`'s policy-resolution LATERAL so
scan-waived (`scan_backends: []`) artifacts are never selected. Update the SQL/port
doc comments. Add `#[serial(hort_pg_db)]` DB-gated tests for every new selection
branch. Run the full pre-push gate.

## Item 3 — Referenced-tree descendants HOLD on `NoAttestation × Required` (+ ADR record)

**Design doc section:** §2 D3 (and §1 rationale re-validation)
**Read first:** `crates/hort-domain/src/entities/artifact.rs`
(`complete_provenance` ~750-850, `cascade_provenance_clearance`),
`crates/hort-app/src/use_cases/provenance_orchestration.rs` (window computation
~255-300, `SkippedAlreadyCleared` ~318+, `apply_verdict` ~1300+),
`crates/hort-app/src/use_cases/ingest_use_case.rs` (the `is_referenced_descendant`
lookup ~2861-2900), `docs/adr/0007-fail-closed-quarantine-release-predicate.md`,
`docs/adr/0039-keyed-provenance-verification.md`
**Acceptance:**
- `Artifact::complete_provenance` takes `is_referenced_descendant: bool`; the
  `NoAttestation × Required` arm holds when `window_open || is_referenced_descendant`;
  every other arm provably ignores the flag (domain tests, 100% — matrix per design
  §4). `cascade_provenance_clearance` unchanged.
- One shared `hort-app` helper implements the descendant predicate (kind ∉
  {`primary_content`, `metadata_blob`}) used by BOTH the ingest anchor decision and
  the orchestrator; the orchestrator resolves it via
  `content_references.find_by_target` and threads it to the verdict; a verdict-time
  lookup failure PROPAGATES (task retry), with the ingest-vs-verdict error-direction
  asymmetry stated in a comment.
- Held descendants surface as `HeldPendingSignature`; no new metric names/values.
- ADR 0007 + ADR 0039 amended per D3 (zero-window § doubles as Required-hold
  predicate; descendant provenance authority = parent signature; D2's widened
  stranded clause; cascade always finds `Quarantined` constituents). ADR scope was
  human-approved at the #115 refined gate — cite that comment in the commit body.
- Workspace gate green; `hort-app` coverage 100% on touched paths.

### Starter prompt

/hort-architect

Implement Item 3 of `docs/plans/115-quarantine-fail-closed-defects-backlog.md` (branch
`agent/115-quarantine-fail-closed-defects`, issue #115 defect (b)). Read design doc §2
D3 + §1 (rationale re-validation) and the files above first. Close the
verify-before-cascade race at the verdict layer: thread
`is_referenced_descendant` from a shared `hort-app` descendant-predicate helper
through `ProvenanceOrchestrationUseCase::apply_verdict` into
`Artifact::complete_provenance`, holding (never terminally rejecting) a descendant on
`NoAttestation × Required` regardless of `window_open`. Do NOT change the ingest
enqueue gate, `cascade_provenance_clearance`, or the `SkippedAlreadyCleared` guard.
Amend ADR 0007 and ADR 0039 exactly as scoped in D3. Restate the acceptance criteria
in your report; run the full pre-push gate.

## Item 4 — E2E: `provenance_mode: Required` × multi-layer proxy pull

**Design doc section:** §2 D4  — depends on Item 3
**Read first:** `scripts/native-tests/README.md` (scenario contract),
`scripts/native-tests/scenarios/quarantine/proxy-multiarch-zero-window.sh`,
`scripts/native-tests/scenarios/quarantine/provenance-push-then-sign.sh`
**Acceptance:**
- New self-describing scenario under `scripts/native-tests/scenarios/quarantine/`:
  signed multi-layer image in the upstream fixture, pulled through a
  `provenance_mode: Required` proxy repo; asserts eventual successful pull and that no
  constituent emits `ProvenanceRejected`.
- Conforms to the scenario contract, appears in `run.sh --list`, shellcheck-clean;
  report states it was authored against the Item-3 behavior (live run rides the
  release-gate E2E; compose is unavailable in the sandbox).
- Workspace gate green (scenario is a script — the gate covers the repo, not a live
  compose run).

### Starter prompt

/hort-architect

Implement Item 4 of `docs/plans/115-quarantine-fail-closed-defects-backlog.md` (branch
`agent/115-quarantine-fail-closed-defects`, issue #115 defect (b) regression E2E;
requires Item 3 already on the branch). Read design doc §2 D4, the scenario contract
in `scripts/native-tests/README.md`, and the two model scenarios above first. Author
the `Required` × multi-layer proxy-pull scenario per the acceptance criteria —
reuse the existing cosign fixture/signing helpers from `provenance-push-then-sign.sh`
and the proxy fixtures from `proxy-multiarch-zero-window.sh`. Shellcheck it, verify
`run.sh --list` picks it up, and state in your report that a live compose run is
deferred to the release-gate E2E.
