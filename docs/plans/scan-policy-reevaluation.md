# Continuous scan-policy enforcement — design + plan

Branch-local planning doc (doc-lifecycle **D7**: reviewed, distilled into
**ADR 0041**, removed before merge to main). Companion to ADR 0041
(*Continuous scan-policy enforcement via stored-findings re-evaluation*).

## §0 — Deferred-items sweep

Grepped `docs/plans/*.md` and the ADR open-items register
(`docs/adr/0000-historical-decisions-index.md`) for
`deferred`/`follow-on`/`out of scope` touching reject / release / re-evaluation /
policy / lifecycle: **no inherited deferred items** beyond the prior 0041 draft
itself, which this supersedes (the per-artifact rescan → folded into ADR 0041's
*Alternatives considered*).

**Re-validated inherited rationale (required):** ADR 0007's fail-closed posture
is reused. Re-verified against this initiative's surface: re-evaluation re-runs
the *same* gate over the artifact's *own stored findings* — it releases only on
passing evidence and re-rejects only on disqualifying evidence (invariants #1,
#4). The posture holds and is *extended* to the tightening direction, not
relaxed. Recorded verdict: **still-valid.** ADR 0040's "persist the fact, derive
the interpretation" rationale is also reused and re-verified: stored findings are
the fact, the policy is the interpretation, re-evaluation is the derivation —
directly consistent.

## §1 — Goal + shape

Make a gate-affecting `ScanPolicy` change re-derive every in-scope artifact's
verdict from its **stored findings** under the new policy, transitioning in both
directions (ADR 0041). No scanner is invoked. Generalises today's
exclusion-only, un-reject-only `run_post_exclusion_re_evaluation_pass` to (a) all
gate-affecting triggers and (b) the tightening direction.

## §1a — Item 0 (FAST-TRACK): fix the existing cross-axis fail-open — ships independently

**This is a live bug on the current branch, not new scope.** `add_exclusion`'s
post-exclusion pass releases on a passing *scan* re-judgement irrespective of why
the artifact was rejected:
`list_rejected_for_policy` (`crates/hort-adapters-postgres/src/artifact_repo.rs:679`)
filters `WHERE a.quarantine_status = 'rejected'` with **no reason filter**;
`re_evaluate_after_exclusion` (`crates/hort-domain/src/policy/re_evaluation.rs:145-181`)
is scan-only; `re_evaluate` (`crates/hort-domain/src/entities/artifact.rs:720-751`)
checks only status + deadline. **Consequence:** adding *any* scan exclusion to a
policy releases *every* provenance- or curation-rejected artifact under it whose
scan passes (e.g. a package blocked by a curation rule, clean scan).

Fix = invariant #6, **three** mechanisms: (a) carry the rejection reason on the
`Artifact` aggregate + guard so only scan-clearable (`reason = Scanner`)
rejections are eligible; (b) an **active provenance** precondition
(`release()`'s timer-arm rule, `artifact.rs:557-558`) in the `re_evaluate`
release path; (c) an **active curation** precondition — reuse
`evaluate_curation` (`policy/curation.rs:142`) over the live rules. (c) is
**not** covered by (a): a scan-rejected artifact matched by a curation rule added
*after* the rejection is NOT re-marked by the retroactive curation pass —
`reject_from_retroactive_curation` skips already-`Rejected` artifacts
(`artifact.rs:351-352` accepts only `Quarantined`/`Released`) — so the reason
guard alone would release it past a live curation block. (b) and (c) are
app-computed clearances passed into the extended `re_evaluate`, mirroring the
`ProvenanceClearance` param on `release()`. Scope it to the **existing**
post-exclusion pass so it lands + ships ahead of the rest of ADR 0041; the
generalised pass (Items 2–3) inherits a correct primitive. Domain 100% incl.
each non-scan reason → not released; provenance-pending → not released;
curation-rule-added-after-scan-rejection → not released.

## §2 — Domain (`hort-domain`) [100% coverage]

**Read first:** `entities/artifact.rs` (`re_evaluate`,
`reject_from_retroactive_curation`, `reject_from_scan`, the apply fold),
`policy/scan.rs` (`evaluate_scan_result`), `policy/re_evaluation.rs`
(`re_evaluate_after_exclusion`), `events/artifact_events.rs`
(`RejectionReason`, `ArtifactReEvaluated`).

- **Retroactive scan transition.** Add the `Released`/`Quarantined` → re-hold
  path for a now-failing verdict, mirroring `reject_from_retroactive_curation`
  (which already accepts a `Released` source). New
  `RejectionReason::ScanPolicyRetroactive` (or reuse `Scanner` with a retroactive
  marker — decide in review). The timer window is **not** re-opened.
- **Generalise the re-evaluation audit event.** `ArtifactReEvaluated` carries a
  non-optional `trigger_exclusion_id`; widen it to a policy-change discriminator
  (which `PolicyUpdated`/`ExclusionAdded`/`ExclusionRemoved` drove the pass) so
  the scanner-tighten/loosen passes can emit it honestly. Append-only schema
  change (ADR 0002).
- **Cross-axis release conjunction (invariant #6).** Extend the `re_evaluate`
  release path so `Rejected → Released` fires only on `scan ∧ curation ∧
  provenance`: the rejection-reason guard (eligibility) + an **active** provenance
  precondition + an **active** curation re-check (reuse `evaluate_curation` over
  the live rules — curation must be mechanized, not proxied by the reason guard;
  see §1a). Provenance + curation clearances are app-computed facts passed into
  the extended `re_evaluate`, mirroring the `ProvenanceClearance` param on
  `release()`. The un-reject side still pairs with authority #5, but `re_evaluate`
  is **extended**, not reused unchanged.
- **One verdict source.** Both directions call `evaluate_scan_result` over the
  artifact's stored findings.
- **Acceptance (100%):** loosen → now-passing `Rejected` releases **only when
  curation + provenance also currently clear**; a provenance-/curation-*rejected*
  artifact with a passing scan stays held (reason guard); a **scan-rejected**
  artifact that a curation rule added *after* the rejection now matches stays held
  (active curation re-check — the case the reason guard misses); a scan-cleared
  artifact with pending provenance stays held; tighten → now-failing `Released`
  re-holds; no-stored-findings artifact is **never** re-rejected on tighten
  (invariant #4); unchanged verdict → no-op; the audit event is emitted on
  transition and not on no-op.

## §3 — Application (`hort-app`) [100% coverage]

**Read first:** `use_cases/policy_use_case.rs`
(`run_post_exclusion_re_evaluation_pass`, `update_policy`, `remove_exclusion`),
`use_cases/apply_config_use_case.rs` (the curation retroactive pass to mirror for
the tightening direction), `ports/artifact_repository.rs`
(`list_rejected_for_policy`), `use_cases/test_support.rs`.

- **Generalise the pass** to `run_policy_re_evaluation_pass(policy_id, trigger)`:
  list the in-scope population, load each artifact's stored findings, evaluate
  against the bumped policy, transition both directions, commit atomically
  (audit + transition) via `commit_transition`.
- **Async + fully paginated — NOT the current 10k-capped synchronous query.**
  Today's pass runs inside the `add_exclusion` request and caps at
  `LIMIT_LIST_MAX_ITEMS` (10 000), truncate-and-warn (`policy_use_case.rs:1062-1076`),
  relying on the next admin action for the remainder. That is tolerable for the
  loosen-only status quo (truncation is fail-closed — stuck stays stuck) but
  **fail-OPEN for tighten** (the >10k remainder stays downloadable, no guaranteed
  next trigger). So: run the generalised pass as a **worker task**, **fully
  paginated** over the whole population (no fixed cap), off the request path. A
  policy mutation enqueues the task and returns.
- **Widen the population port:** add a paginated `list_active_for_policy`
  (the `Released` / `Quarantined` scanned set) alongside `list_rejected_for_policy`;
  DB-backed tests carry `#[serial(hort_pg_db)]`.
- **Wire the triggers:** `update_policy` (gate fields), `remove_exclusion`,
  `reactivate_policy` enqueue the task; `add_exclusion` is migrated onto it.
- **Acceptance (100%):** each trigger enqueues the pass; both directions; the
  no-evidence no-op; idempotent; paginates past 10k (no silent truncation);
  outcome metric (`released` / `re_held` / `unchanged`) + a completeness signal;
  audit events — ports mocked via `use_cases/test_support.rs`.

## §4 — Cross-opt-in guards (ADR 0016 / 0041 matrix)

- `scan_backends: []` → no scanner invoked; waiver-released artifacts have no
  findings → untouched. The prior draft's "refuse when no backend" guard is
  **removed**.
- `provenance_mode: Required` → release is `scan ∧ provenance` (∧ curation). This
  does **not** compose for free — the `re_evaluate` path ignores provenance today
  (invariant #6 / §1a); it must be *made* to compose, and doing so fixes the
  pre-existing fail-open.
- `trust_upstream_publish_time` → verdict-only; no timer interaction.

## §5 — Observability

- `info!` on each state-changing transition (release / re-hold) and on
  pass-start with the trigger + in-scope count (security-relevant: a tighten
  pulls artifacts). `#[instrument(skip(self))]` (no `err`) on the use-case
  methods; no-ops stay `debug!`.
- New outcome metric `hort_policy_reevaluation_*{result}` —
  **update `docs/metrics-catalog.md` in the same PR** (label `result` ∈
  `released` / `re_held` / `unchanged`; no high-cardinality labels). The pass
  must also surface **completeness** (pages processed / population covered) so a
  truncated or aborted tighten pass is observable, never silent.
- `warn!` on a per-artifact transition/commit failure that the pass skips
  (bounded — one bad artifact must not abort the population pass).

## §6 — Tests that pin the behaviour locally (no release-to-find-out)

- Domain + app acceptance sets above.
- Load-bearing red→green (tighten): a **tighten** (`negligible_action: Block`, or
  a lowered threshold) re-holds a previously-`Released` artifact whose stored
  findings now disqualify (fails today — the fail-open gap), and a **no-findings**
  artifact is untouched by the same tighten (the evidence guard).
- Load-bearing red→green (§1a, existing bug): adding a scan exclusion to a policy
  does **not** release a **provenance- or curation-rejected** artifact under it
  whose scan passes (fails today — the cross-axis fail-open); a scan-cleared
  artifact with **pending provenance** is **not** released; and a
  **scan-rejected** artifact matched by a curation rule added *after* the scan
  rejection is **not** released (the active curation re-check — the case the
  reason guard alone misses).

## §7 — Docs

- Update the operator how-to (`docs/architecture/how-to/`): policy changes are
  retroactive in both directions; what a tightening pulls; the
  stored-findings/evidence model. ADR 0041 → Accepted; ADR index row added.
- Remove this plan doc before merge to main (D7).

## §8 — Explicitly out of scope

- **Tightening preview / dry-run** ("how many would this pull?"). Real operator
  safety tooling; a follow-on. Deferral is acceptable **because** §3 makes the
  pass async + observable (completeness metric) — the floor that lets the preview
  wait. Carried forward — see ADR 0041 §Blast-radius.
- **Corrective rescan** (refresh stored findings for a buggy/stale scanner). A
  separate, narrower concern that *feeds* this mechanism (refresh → re-evaluate);
  the admin-rescan path already records fresh findings. Carried forward — scope a
  follow-on plan if a findings-changed trigger is wanted.
- **Curation/scan-policy pass unification into one engine.** This initiative
  brings scan-policy onto the same *principle* as curation; physically merging
  the two passes is a later refactor. Carried forward.
- **Periodic reconciliation tick for missed enqueues.** A cron-driven backstop
  that re-enqueues a re-eval pass for any policy whose projection version is
  ahead of the last completed pass — the robust recovery beyond the v1
  alertable signal (`hort_policy_reevaluation_enqueue_failed_total`, MR !48
  review). The counter tells an operator a pass *never ran*; the tick would
  close the loop automatically (track a per-policy `last_reevaluated_version`,
  enqueue when it lags the projection version). Carried forward — scope a
  follow-on plan; the counter is the v1 signal until then.
