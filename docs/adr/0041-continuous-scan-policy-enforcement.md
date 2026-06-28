# 0041 — Continuous scan-policy enforcement via stored-findings re-evaluation

- **Status:** Accepted
- **Replaces:** the earlier draft of this ADR (a per-artifact, admin-triggered
  *rescan*-to-un-reject — "sixth release authority"), which is folded into
  *Alternatives considered* below.
- **Relates to:** [0002](0002-event-sourced-artifact-lifecycle.md) (event-sourced
  lifecycle), [0007](0007-fail-closed-quarantine-release-predicate.md) (the
  fail-closed release predicate this preserves), [0015](0015-apply-time-linter-inert-fields-and-naming.md)
  (a policy field accepted at apply must be enforced at runtime),
  [0016](0016-cross-opt-in-interaction-matrix.md) (cross-opt-in matrix),
  [0040](0040-osv-informational-negligible-lane.md) (the "persist the fact,
  derive the interpretation" precedent and the motivating case).

## Context

A `ScanPolicy` decision today is **point-in-time at ingest** for the scan axis:
an artifact is scanned, quarantined, and released-or-rejected against the policy
*as it was* when the artifact was ingested. Changing the policy afterwards does
not re-examine the artifacts already decided under it — with one partial
exception (`add_exclusion`) and one inconsistency (curation).

The as-built behaviour, verified against the code:

| Config change | Direction | Re-evaluates the existing population? | Failure mode if not |
|---|---|---|---|
| `add_exclusion` | loosen | **Yes** — `run_post_exclusion_re_evaluation_pass` | fail-closed (safe) |
| `update_policy` (threshold / blocked class / `negligible_action`) loosen | loosen | **No** | fail-closed (artifacts stay stuck) |
| `remove_exclusion` | **tighten** | **No** | **fail-OPEN** |
| `update_policy` tighten (raise bar / add class / `negligible_action: Block`) | **tighten** | **No** | **fail-OPEN** |
| `CurationRule` create/tighten | **tighten** | **Yes** — `apply_curation_rules` → `reject_from_retroactive_curation` (transitions even `Released`) | (handled) |

Two problems follow.

1. **An undecided inconsistency.** Curation (name/pattern blocks) is enforced
   *retroactively* — a tightened rule re-rejects already-`Released` artifacts.
   Scan-policy (severity/finding blocks) is **not** — `update_policy` triggers
   no re-evaluation at all, and `reject_from_scan` even refuses a `Released`
   source. Pattern blocks are retroactive; evidence blocks are frozen. Nobody
   decided that for the scan axis.

2. **The risk is lopsided, and the dangerous side is the unhandled one.** A
   *loosening* that fails to re-evaluate is mere operator inconvenience — the
   artifact stays blocked, which is safe (fail-closed). A *tightening* that
   fails to re-evaluate means an artifact the operator has just declared
   **unacceptable stays downloadable** — fail-open. The scan axis has no
   tightening path.

The real driver is a population, not an artifact: when an operator realises a
policy was mis-set (too tight *or* too loose) — or a compliance requirement
changes — they expect the *existing* artifacts to be re-judged under the new
policy, in both directions.

## Decision

**Scan-policy is continuously enforced.** The durable per-artifact scan
**findings** are the evidence; the **policy** is the interpretation. Whenever a
gate-affecting policy change occurs, Hort **re-derives each in-scope artifact's
verdict from its stored findings under the new policy** and transitions the
artifact to match — in **both** directions:

- now-passing `Rejected` → `Released` / re-`Quarantined`
  (reuses release authority #5, `PolicyReEvaluation` — **no new authority** — but
  the `re_evaluate` path must be *extended* to apply the cross-axis release
  conjunction of invariant #6; this is new composition logic, not free reuse);
- now-failing `Released` / `Quarantined` → re-`Quarantined` / re-`Rejected`
  (a retroactive scan transition, mirroring curation's retroactive block);
- unchanged verdict → no-op.

Re-evaluation **does not run a scanner.** It reads the stored findings
(`scan_findings`, the per-finding rows already persisted at scan time) and
re-runs the *same* pure evaluator (`evaluate_scan_result`) against the new
policy. The scanner is the source of the *evidence*; it is not consulted to
re-interpret it.

Five invariants, each preserving a foundation:

1. **Evidence-based and fail-closed (ADR 0007 preserved).** Re-evaluation
   re-applies the **same** release gate over stored findings. An artifact is
   re-rejected only when its **own stored evidence** crosses the tightened gate;
   it is released only when its stored evidence passes — never on a timer, never
   by fiat. No "fall-through to released", no degraded authority. The un-reject
   path keeps using authority #5; the release predicate stays enumerated and
   unchanged.
2. **Both directions derive from one evaluation.** Loosening clears
   now-passing rejections; tightening re-holds now-failing releases. Both come
   from the same `evaluate_scan_result` over the same stored findings, so the
   two directions cannot diverge or contradict.
3. **Audited (ADR 0002).** Every transition *appends* a re-evaluation audit
   event plus the transition event; no past event is mutated. The audit names
   the policy change (the `PolicyUpdated` / `ExclusionAdded` / `ExclusionRemoved`
   event) that drove it.
4. **No evidence ⇒ no re-rejection.** An artifact with no stored findings
   evaluates clean and is **never** re-rejected by a scan-policy tighten — there
   is no evidence it violates. (A scope released by waiver — `scan_backends: []`
   — has no findings, so it is untouched. Genuinely-unscored-but-quarantined
   artifacts keep ADR 0007's Critical fail-closed at their original gate; a scan
   tighten cannot manufacture a violation without evidence — that is the
   curation axis's or an admin's job, not this one.)
5. **Consistency with curation.** Curation's retroactive tighten becomes one
   instance of continuous enforcement, not a special case; scan-policy joins the
   same model.
6. **Release is the cross-axis conjunction `scan ∧ curation ∧ provenance`** —
   each conjunct *mechanized*, none merely proxied. A `Rejected` artifact is
   released only when every gate that could hold it currently clears, not on a
   passing scan re-judgement alone. This is not the status quo: the existing
   post-exclusion pass releases on scan-pass irrespective of *why* the artifact
   was rejected (`list_rejected_for_policy` filters `quarantine_status = 'rejected'`
   with no reason filter; `re_evaluate` checks only status + deadline), so adding
   a scan exclusion can today release a provenance- or curation-rejected artifact
   whose scan passes — a live fail-open. The fix is **three** mechanisms, not two:
   - (a) **Rejection-reason guard (eligibility).** Only a scan-clearable rejection
     (`reason = Scanner`) is a candidate for a scan re-judgement; every *other*
     reason — provenance-rejected, curation-rejected, corruption, admin — is
     ineligible (the artifact must carry its rejection reason; it does not today).
     A reject reason added later is ineligible by default.
   - (b) **Active provenance precondition.** For an eligible (scan-rejected)
     artifact, also require provenance to currently clear — the AND-precondition
     `release()`'s timer arm already applies (`artifact.rs:557-558`) — so a
     scan-cleared artifact with pending/failed provenance is not released.
   - (c) **Active curation precondition.** Symmetric to (b): also require that no
     currently-active curation rule matches the artifact (reuse
     `evaluate_curation`). The reason guard does **not** cover this — a
     *scan*-rejected artifact (eligible) that a curation rule added *after* the
     scan rejection would block is **not** re-marked by the retroactive curation
     pass (`reject_from_retroactive_curation` transitions only `Quarantined` /
     `Released`, never an already-`Rejected` artifact), so without an active
     re-check a scan loosen releases it past the live curation block.

   (b) and (c) are verified facts the application layer computes from the live
   provenance state and curation rules and passes into the extended `re_evaluate`
   (mirroring the `ProvenanceClearance` param on `release()`); the domain stays
   pure.

### Triggers and scope

Gate-affecting `ScanPolicy` mutations run a bounded re-evaluation pass over the
policy's in-scope population: `add_exclusion` (already), `remove_exclusion`,
`update_policy` for the gate fields (severity thresholds, blocked classes,
`negligible_action`), and `reactivate_policy`. The pass generalises today's
`list_rejected_for_policy` (un-reject only) to the full active set
(`Rejected` **and** `Released` / `Quarantined` scanned artifacts).

### Blast-radius and operational safety (the tightening direction is high-impact)

- The pass runs **async (a worker task), off the policy-mutation request path,
  and fully paginated over the whole in-scope population — no fixed cap.** (The
  existing post-exclusion pass's 10 000-row truncate-and-warn is fail-open in the
  tighten direction and is replaced.) It is **idempotent** (re-running yields the
  same verdict), emits one transition per changed artifact, and surfaces a
  **completeness** signal so a partial pass is observable, never silent.
- Re-rejecting a `Released` artifact blocks **future** downloads (the status
  gate); already-served bytes cannot be recalled — the audit records the moment
  of non-compliance. Closing the door forward is strictly better than leaving it
  open.
- A **preview / dry-run** ("how many artifacts would a tightening pull?") is
  desirable operator safety tooling — a follow-on, not required for this stance.

### Cross-opt-in interaction matrix (ADR 0016)

| Opt-in | Interaction | Disposition |
|---|---|---|
| `scan_backends: []` (ScanWaived) | Re-evaluation reads stored findings; it invokes **no** scanner. Waiver-released artifacts have no findings → untouched. | No interaction — and the prior draft's "refuse when no backend" guard is **dropped** as unnecessary. |
| `trust_upstream_publish_time` | Anchors the quarantine *deadline*. Re-evaluation re-derives the *verdict*, not the timer; tightening re-holds independent of the deadline. | No interaction. |
| `provenance_mode: Required` | The release gate must be `scan ∧ provenance` (∧ curation). **The reused `re_evaluate` path does NOT check provenance today** (`artifact.rs` checks only status + deadline), and the existing post-exclusion pass already releases provenance/curation-rejected artifacts whose scan passes (invariant #6). | **Must be *made* to compose** — new composition logic that also fixes a pre-existing fail-open; not free reuse. |

No combination collapses a gate invariant: re-evaluation is the same fail-closed
gate re-run over the artifact's own evidence.

## Consequences

- **The fail-open tightening gap closes.** Tightening a scan policy — raising the
  bar, adding a blocked class, `negligible_action: Block`, or removing an
  exclusion — now pulls the now-non-compliant population.
- **The loosening case is served without a rescan**, and works under
  `scan_backends: []`. The per-artifact-rescan draft's "no scanner to recalculate"
  guard problem disappears entirely.
- **The ADR 0040 negligible-lane case resolves honestly at population scale.**
  Flipping `negligible_action` re-derives every affected artifact's verdict from
  its stored class fact — no CVE-waiver abuse (which would mislabel informational
  advisories as accepted vulnerabilities), no rescan.
- **Curation and scan-policy retroactivity unify** under one principle.
- **No new release *authority* — but new release *composition*.** The un-reject
  direction reuses authority #5 (`PolicyReEvaluation`); ADR 0007's enumerated
  predicate gains no arm, and the old draft's sixth authority + `scan_backends:[]`
  guard are gone. It does **not** follow that the loosen direction is free reuse:
  the `re_evaluate` path must gain the cross-axis conjunction of invariant #6
  (reason guard + provenance precondition), and landing that fixes a pre-existing
  fail-open in the existing post-exclusion pass.
- **New surface to build:** the cross-axis release conjunction (invariant #6) +
  rejection-reason carriage on the artifact aggregate; the re-evaluation pass
  generalised to both directions and run **async + fully paginated** (not the
  current 10k-capped synchronous query — truncation is fail-open in the tighten
  direction); a `list_*_for_policy` over the active population; a retroactive
  scan re-reject / re-quarantine transition + `RejectionReason`; and a
  generalised re-evaluation audit event — today's `ArtifactReEvaluated` is
  exclusion-shaped (a non-optional `trigger_exclusion_id`) and must be widened to
  "policy-change-driven", carrying which policy event drove the pass. Handled
  append-only (ADR 0002).
- **A policy change is no longer O(1):** it enqueues a paginated population pass.
  Acceptable — `add_exclusion` and curation already trigger population work.

## Alternatives considered

- **Per-artifact admin rescan-to-un-reject (the earlier draft of this ADR).**
  Rejected: covers one corner of a 2×2 (un-reject only), always runs a fresh
  scanner (wasteful, and impossible under `scan_backends: []`), is manual
  per-artifact (a poor fit for a population created by a config change), and
  leaves the fail-open tightening direction untouched.
- **Frozen-at-ingest (status quo): scan-policy is point-in-time, never
  re-evaluated.** Rejected: leaves the fail-open tightening gap, is inconsistent
  with curation's retroactive enforcement, and pushes operators toward CVE-waiver
  abuse to clear over-rejected artifacts.
- **Rescan-based re-evaluation (re-run the scanner on policy change).** Rejected:
  the policy is the interpretation, not the evidence. Re-running the scanner
  conflates "the gate changed" with "the evidence changed", makes release depend
  on scanner availability, and cannot run on a waived scope. The stored findings
  already *are* the evidence. (A corrective rescan that *refreshes* stored
  findings — for a buggy or stale scanner — is a separate, narrower concern that
  *feeds* this mechanism: refresh the findings, then re-evaluation re-derives the
  verdict.)
- **CVE exclusion as the universal clearing tool.** Rejected (per ADR 0040):
  records informational / below-threshold findings as knowingly-accepted
  vulnerabilities, polluting the policy with non-waivers; and cannot express
  tightening at all.

## References

- `crates/hort-app/src/use_cases/policy_use_case.rs` —
  `run_post_exclusion_re_evaluation_pass` (the un-reject pass this generalises),
  `update_policy` (the trigger that today re-evaluates nothing).
- `crates/hort-domain/src/policy/scan.rs` (`evaluate_scan_result`),
  `re_evaluation.rs` (`re_evaluate_after_exclusion`) — the pure evaluators reused
  over stored findings.
- `crates/hort-domain/src/entities/artifact.rs` — `re_evaluate`
  (`Rejected → Released/Quarantined`), `reject_from_retroactive_curation`
  (`Released → Rejected`, the retroactive-tighten precedent).
- `crates/hort-domain/src/ports/scan_findings_repository.rs` — the stored-findings
  evidence (`scan_findings`, migration 009).
- ADR 0002 (append-only audit), ADR 0007 (the preserved release predicate),
  ADR 0016 (the matrix), ADR 0040 (the persist-fact/derive-interpretation
  precedent and the motivating case), and the curation retroactive path.
- Design doc: `docs/plans/scan-policy-reevaluation.md` (branch-local
  implementation plan; distilled here and removed before merge to main).
