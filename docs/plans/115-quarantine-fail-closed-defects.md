# #115 — Fail-closed quarantine defects: seed-import strand + zero-window descendant × `provenance_mode: Required`

Issue: #115 (source: audit #106 finding M6, adversarially verified; spec approved by the
human 2026-08-05). Feature branch: `agent/115-quarantine-fail-closed-defects`.
Branch-lifetime planning doc (D7): distill durable decisions into the ADR set before any
merge to `main`; this file never leaves the branch line.

## §1 Scope, deferred-items sweep, rationale re-validation

Two independent MEDIUM fail-closed defects (availability/contract, not exposure):

- **(a) Seed-import stranded.** `IngestUseCase::register_by_hash_inner`'s
  `quarantine_anchor_override` branch (the seed-import cutover,
  `ingest_use_case.rs` ~3766+) appends `ArtifactQuarantined` with the backdated anchor
  but enqueues **no scan job** — unlike `ingest_inner`, which lands `ScanRequested` +
  `IngestEnqueue::Scan` atomically with the quarantine transition
  (`commit_transition_with_enqueues`, ADR 0002/0004 no-strand). Neither sweep recovers
  it: `select_eligible` requires `quarantine_status = 'released' OR IS NULL`
  (`rescan_candidates.rs:117-119`); `select_stranded` LATERAL-joins the most recent scan
  job and requires `status = 'failed'` (`:198-209`) — an artifact with **no job row
  produces no join row**. Under ADR 0007 the release predicate requires
  `ScanSucceeded`/`ScanWaived`/admin — so every seed-imported artifact under a scanning
  policy 503s (`Retry-After: 1`) indefinitely. The seed-import module doc's "next sweep
  releases it on a clean scan" is false today — that scan is never requested.
  **Grooming finding:** there is NO manual per-artifact rescan surface (no admin
  enqueue-scan endpoint, no CLI); already-stranded rows in deployed envs are
  unrecoverable without D2. That promotes the sweep-widening from "alternative" (issue
  text) to load-bearing remediation alongside the at-source fix.

- **(b) Zero-window descendant × `Required`.** Referenced-tree descendants get a
  zero-length window by design (#46: anchor = `ingested_at − duration`,
  `ingest_use_case.rs` ~2861-2941); the OCI pull-through edge writer records
  `oci_config`/`oci_layer` references before blobs are pulled, so each layer ingests as
  a zero-window descendant and (format-capable, mode ≠ Off) enqueues
  `provenance-verify`. The verifier finds no bundle for a layer digest (cosign signs
  only the top-level digest) → `NoAttestation` × `Required` × `window_open == false` →
  **terminal `Rejected{Unsigned}`** (`artifact.rs:830-843`). The later subject-signature
  cascade refuses rejected constituents (`cascade_provenance_clearance`: "terminal is
  terminal") → the signed image is permanently unpullable. The codebase already guards
  the *inverse* ordering (`SkippedAlreadyCleared`: re-verifying a cascade-cleared
  constituent would wrongly reject it) — the gap is the constituent verified *before*
  its subject's cascade.

**Deferred-items sweep (Step 0, run 2026-08-05).** `docs/plans/` on `develop` carries
only the #113 metrics plans (no quarantine/provenance deferrals). ADR 0000 open-items
register hits in this initiative's area, none absorbed:
"Combined real-verifier provenance E2E" (keyless-variant gap — different axis from D4's
new proxy-pull scenario; stays open, not touched); "OCI image-index child-status
rollup" and "index promotion cascade" (index-level UX/promotion concerns, unrelated to
the constituent-rejection defect; carried forward unchanged); "scan-policy re-eval
reconciliation tick", Maven/Gradle items (out of area). No other inherited deferred
work applies.

**Inherited-rationale re-validation (Step 0.5).** The #46 zero-window rationale ("the
release predicate is unchanged; the window is pure latency for every artifact, not
protection" — §4a, mirrored in the `is_referenced_descendant` comment block) is
**reversed here, scoped**: it was written against the *scan* release authority and
missed that `window_open` had become load-bearing as the **hold predicate** for the
`NoAttestation × Required` provenance arm (issue #13). For descendants the window is
not pure latency — closing it flips "held pending signature" to "terminally rejected".
D3 restores the hold for descendants without reopening #46's timer removal (the
carve-out's actual goal). The `Required`-mode interaction was also never recorded in
the ADR 0016-style interaction surface — D3 closes that documentation gap in ADR 0007
(zero-window section) + ADR 0039. Note: the zero-window carve-out is automatic (not an
operator opt-in), so this is an ADR-prose interaction record, not a new ADR 0016 matrix
row/linter rule.

**Explicitly out of scope.** (i) #107 (`register_by_hash` bypasses Gate-2 on the OCI
cross-repo mount + pull-dedup follower paths — HIGH, `agent:escalation`, in
specification): D1 fixes only the seed branch (`quarantine_anchor_override = Some`);
the mount/follower callers pass `None` and stay as-is for #107's own initiative. D1's
shape (gate resolution inside `register_by_hash_inner`) is deliberately reusable by
#107. (ii) A manual per-artifact rescan admin surface — D2 makes the sweep the
remediation; a bespoke endpoint is unjustified surface. (iii) Keyless-provenance E2E
(open-items row). (iv) Seed-import support for OCI/referenced trees (v1 path shape is
`<name>/<version>`).

## §2 Decisions

### D1 — Seed path mirrors `ingest_inner`'s atomic enqueue gate (defect a, prevention)

In `register_by_hash_inner`, the `quarantine_anchor_override = Some(anchor)` branch
resolves the active policy for the target repo (same
`resolve_active_policy_for_repo`-based resolution `ingest_inner` uses — `self.policies`
is already on `IngestUseCase`; no request-shape change, no new port) and computes the
same two gates as `ingest_inner`:

- `scan_will_run = matched_policy.map(|p| !p.scan_backends.is_empty()).unwrap_or(!DefaultPolicy::block_on_critical_default_backends().is_empty())`
- `provenance_will_run = mode != Off && provenance_capable_formats.contains(format)`

The quarantine follow-on commit becomes `commit_transition_with_enqueues`, landing
`ArtifactQuarantined` + (gated) `ScanRequested` + `IngestEnqueue::Scan` /
`IngestEnqueue::ProvenanceVerify { trigger_source: "seed-import" }` in ONE transaction
(ADR 0002/0004 no-strand; scan enqueue idempotent at the adapter). `ScanWaived`
policies (`scan_backends: []`) enqueue nothing and release at the (already expired)
deadline via the existing `ScanWaived` authority — unchanged.

Consequence to document (module doc + report, not code): seed-import into a
`provenance_mode: Required` repo with a capable format = immediate terminal
`Rejected{Unsigned}` for unsigned content (zero window, not a descendant). That is the
policy-consistent fail-closed outcome — Required means unsigned content does not
release; operators seed unsigned content into non-Required repos.

### D2 — `select_stranded` recovers job-less quarantined artifacts, scan-policy-aware (defect a, cure)

Widen `RescanCandidatesRepository::select_stranded` (adapter SQL): replace the
inner `JOIN LATERAL (last scan job)` + `last_job.status = 'failed'` with a
`LEFT JOIN LATERAL` and predicate `(last_job.status = 'failed' OR last_job.status IS
NULL)` — i.e. "most recent attempt failed **or no scan was ever requested**". Keep
`quarantine_status = 'quarantined'`, `is_deleted = false`, and the
no-pending/running exclusion. ADD a resolved-policy guard reusing `select_eligible`'s
repo-scoped-else-global policy LATERAL: candidates qualify only when
`COALESCE(cardinality(p.scan_backends), <default-policy-len>) > 0` — a job-less
quarantined artifact under a **scan-waived** policy is NOT stranded (it releases via
the `ScanWaived` authority) and must not receive an operator-contradicting scan
enqueue. Default-policy fallback scans (trivy), matching `DefaultPolicy`.

This heals every pre-fix stranded seed import automatically (bounded by
`batch_size` per tick — large imports drain over several ticks; acceptable, and D1
removes the inflow) and is the standing defense for the quarantined-without-job class
(#107's paths included, until its own fix lands). ADR 0007's rescue-path description
("the failed jobs row is the signal") gains the "or no job row at all" clause — D3's
ADR touch carries it.

### D3 — Descendants HOLD (never terminally reject) on `NoAttestation × Required` (defect b)

Close at the **verdict layer** — the single choke point every path funnels through
(ingest-enqueued verify, S4 expiry-backstop re-verify, duplicate S3 enqueues) — rather
than skipping the ingest enqueue (which would leave S4/duplicate enqueues able to
reject, the same bug via another door; mirrors the reasoning that produced
`SkippedAlreadyCleared`).

- `hort-domain`: `Artifact::complete_provenance` gains
  `is_referenced_descendant: bool`; the `NoAttestation × Required` arm holds
  (`Ok(None)`, status stays `Quarantined`) when `window_open ||
  is_referenced_descendant`. All other arms ignore the flag (a forged/untrusted
  signature on a descendant still rejects — time-independent, exactly like
  `window_open`). `cascade_provenance_clearance` unchanged.
- `hort-app`: extract the descendant predicate shared with ingest into one helper
  (`is_referenced_tree_descendant(refs) -> bool`: any `content_references` target row
  whose `kind ∉ {primary_content, metadata_blob}`); `ProvenanceOrchestrationUseCase`
  resolves it via `content_references.find_by_target(repo_id, hash, None)` before
  applying a verdict and threads it through `apply_verdict` → `complete_provenance`.
  **Error direction:** a failed lookup at verdict time PROPAGATES (job fails →
  dispatcher retry). Degrade-to-`false` is correct at ingest (falls back to the FULL
  window — conservative) but at verdict time it falls toward TERMINAL rejection — the
  unsafe direction. State this asymmetry in a comment at the call site.
- Held descendants map to the existing `HeldPendingSignature` verdict summary (no new
  metric names, no new `result` values — catalog untouched).
- Ingest-time enqueue gate: UNCHANGED (descendants still enqueue verify; the job
  closes as held — one no-op job per constituent is the price of a single close
  point).
- Steady state: an unsigned parent under `Required` leaves constituents `Quarantined`
  forever (held, 503) — fail-closed and recoverable (sign later → S3 hook → subject
  verifies → cascade clears; or admin release per ADR 0025 source-state rules). This
  replaces today's unrecoverable terminal rejection.
- ADR record (gated per the ADR-change rule — see refinement comment): amend ADR 0007
  (zero-window section: the window doubles as the Required-mode hold predicate;
  descendants' provenance authority is their parent's signature; plus D2's widened
  stranded clause) and ADR 0039 (cascade section: descendant-hold guarantees the
  cascade always finds `Quarantined` constituents, closing the
  verify-before-cascade race).

### D4 — Targeted E2E: `Required` × multi-layer proxy pull

New self-describing scenario `scripts/native-tests/scenarios/quarantine/`
(name e.g. `proxy-required-multilayer.sh`), modelled on
`proxy-multiarch-zero-window.sh` (proxy + zero-window assertions) and
`provenance-push-then-sign.sh` (cosign signing, Required-mode gitops fixture): sign a
multi-layer image in the upstream fixture registry, pull through a
`provenance_mode: Required` proxy repo, assert the pull eventually succeeds and that
NO constituent emits `ProvenanceRejected` (the defect's signature). Runs under
`--group quarantine`; live verification rides the release-gate E2E runs (compose is
not available in the cockpit sandbox — authoring + contract conformance is the item's
gate, plus the reproduction assert documented in the report).

## §3 Observability

No new metric names or label values (catalog untouched). D1: the seed-path enqueues
reuse the existing ingest-enqueue instrumentation; `trigger_source: "seed-import"`
distinguishes job rows (column value, not a metric label). D2: existing
`select_stranded` debug tracing suffices; the rescan tick's existing counters cover
enqueue volume. D3: descendant hold logs `debug!` (routine, high-volume per layer);
the terminal-rejection arm's existing `info!`-level event flow is unchanged. Any
deviation discovered by the cockpit (e.g. a `result_summary` value that must be
added) requires a `docs/metrics-catalog.md` update in the same change per the
standing rule.

## §4 Test plan

- D1: `hort-app` 100% — unit tests on the seed branch: scan enqueued under scanning
  policy; nothing enqueued under `scan_backends: []`; provenance enqueued iff
  `mode ≠ Off` ∧ capable format; atomicity shape (single
  `commit_transition_with_enqueues` call observed by the mock lifecycle);
  `SeedImportUseCase` module-doc claim corrected.
- D2: `hort-adapters-postgres` ≥85% — DB-gated integration tests (**every new test
  carries `#[serial(hort_pg_db)]`**): job-less quarantined artifact selected;
  job-less + scan-waived policy NOT selected; failed-job case still selected
  (regression); pending/running exclusion; released/rejected/scan_indeterminate/
  deleted never selected.
- D3: `hort-domain` 100% — exhaustive `complete_provenance` matrix over
  `is_referenced_descendant` × existing arms (descendant × NoAttestation × Required ×
  window-closed → holds; descendant × Rejected-verdict → still rejects; flag inert
  under VerifyIfPresent/Off and for Verified). `hort-app`: orchestrator threads the
  flag; lookup-error propagates (no verdict applied); shared helper unit-tested; the
  existing `SkippedAlreadyCleared` tests stay green.
- D4: scenario passes `run.sh --list` inventory + scenario-contract conventions
  (`scripts/native-tests/README.md`), shellcheck-clean.
