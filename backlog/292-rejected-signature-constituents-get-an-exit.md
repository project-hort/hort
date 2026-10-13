# 292 — The rejected signature constituents get an exit

**Issue:** #342 · **Branch:** `agent/342-referenced-blob-deliverability`
**Governing decisions:** ADR 0039's 2026-09-12 amendment (D1, D6) and
ADR 0041 invariant #6(a) — a scan re-judgement must never clear a provenance
rejection, which is why this is a narrower sibling transition and not a
widening of `Artifact::re_evaluate`'s guard.

**Depends on:** item 291. This unit consumes 291's signature-constituent
predicate as its authority and must not re-derive it. It is in turn the
**precondition for item 294**.

## What is true today

The forward-looking exemption (291) changes nothing about the rows already in
the state. **Measured on the dogfood instance** — not on a separate production
deployment; it is the only instance carrying live data, and "production" in an
earlier revision of this item overstated that. ~2.5k rejected signature
payloads plus the six `{}` config rows (created 2026-07-02 … 2026-08-09) are
reachable by **no existing operator action**:

**The population is closed, and that is load-bearing for the decision below.**
The last terminal rejection of a signature payload is 2026-08-15, with zero in
September and zero in October; they were created under 0.9.13 / 0.11.0-beta.x
and the defect that produced them is fixed (ADR 0039 D1/D6). The sibling
`quarantined` population is unaffected and still growing normally. So this is
legacy stock, not an ongoing leak — but it is legacy stock as **live rows**:
`deleted_at IS NULL`, so an ingest deduplicates onto them rather than creating
a new artifact.

**Therefore the first question is not (A) vs (B) but whether that database has
to survive at all.** If it can be reset or rebuilt, this unit drops entirely
and item 294 loses its dependency on it. Only if the stock must survive does
the (A)/(B) choice below arise.

- `POST /admin/curation/quarantine/:id/reevaluate` answers `still_rejected`
  and writes nothing — `Artifact::re_evaluate`'s eligibility guard admits only
  a *scan-clearable* rejection, and a provenance rejection leaves
  `rejection_reason = None`, which is fail-closed ineligible. That refusal is
  correct and must stay.
- **`waive` now reaches them one at a time — corrected 2026-10-11, after #345
  merged.** This bullet used to read *"`release` / `waive` never applies — the
  source-state guard admits only `Quarantined` / `ScanIndeterminate`"*, and that
  is no longer true. #345's `Rejected` override admits the **provenance axis**
  (`is_curator_overridable`), and the use case re-hydrates the axis from the
  stream via `scan_history::last_rejection_reason`, which reads the latest
  `ArtifactRejected`'s `rejected_by` regardless of axis. These rows carry
  `ArtifactRejected { Provenance }`, so a curator waive on one of them is
  **eligible today**: it releases, clears the rejection, and records
  attribution plus a justification.

  **What this unit still adds, and what it no longer claims.** It no longer
  claims the population is reachable by *no* operator action. It claims that
  **~2.5k individually-justified curator waives are not an operator
  procedure**: the corrective path here is one admin-gated, dry-run-by-default,
  system-attributed run over a recognised population, which is a different
  instrument from a human decision about one artifact. **That is a scope
  question the maintainer should settle before this unit starts** — bulk repair,
  or curatorial processing of the backlog with this unit dropped. Everything
  else in this section stands as measured.
- **The existing repair endpoint refuses them, by its own correct design.**
  `POST /admin/quarantine/provenance-misrejections/repair`
  (`crates/hort-app/src/use_cases/provenance_misrejection_repair.rs`) requires
  as its third conjunct a `ProvenanceVerified` **on the stream**: it withdraws
  a rejection that the artifact's own stream *contradicts*. These rows have no
  `ProvenanceVerified` and — this is the whole point of 291 — can never get
  one. The endpoint is right to refuse them; it is answering a different
  question.
- Re-pushing heals nothing: the row exists with `deleted_at IS NULL`, so the
  ingest deduplicates onto it instead of creating a new one.

So this population needs code, not an operator run of something that already
ships. Without this unit, item 294's read-time rule would strand the entire
signature inventory even after 291.

## What to do

1. **Reuse the existing corrective surface; add the second recognised
   population.** The admin-gated, dry-run-by-default, one-shot shape is
   already argued for in `provenance_misrejection_repair.rs`'s module doc
   (bounded, historical population; an operator who has read what it will
   touch; `Permission::Admin` per ADR 0038, so no pipeline can invoke it).
   Do not build a startup reconciliation or a periodic task handler — that
   rationale holds for this population too.
2. **Change exactly one conjunct.** Conjuncts 1 (`quarantine_status ==
   Rejected`) and 2 (`TerminalRejectionRecord::Absent` — the stream records no
   terminal condemnation) are shared and stay as they are, including the
   corruption-tombstone classification. Conjunct 3 is what differs: instead of
   *"the stream contradicts this rejection"* (a `ProvenanceVerified`), the
   authority is *"the rule that produced this rejection cannot apply to this
   artifact"* — i.e. 291's signature-constituent fact, resolved in the
   application layer and handed to the domain as a verified fact, the same
   shape every other stream-derived conjunct uses.
3. **A sibling domain transition, not a loosened one.** A second named
   method beside `Artifact::repair_provenance_misrejection` whose doc states
   its own three conjuncts, or one method taking a named authority — the
   implementer's call, with one constraint: **no code path may reach the
   `Rejected → Quarantined` transition without naming which of the two
   authorities it carries.** The exit is unchanged: `Rejected → Quarantined`
   with the **original** observation-window anchor preserved (never restarted)
   and `rejection_reason` cleared, so the row lands back in front of the
   ordinary release sweep, which applies the live scan / curation / provenance
   gates. With 291 in effect that sweep releases it on the scan axis.
4. **A distinct `ReEvaluationTrigger` variant.** The existing
   `ProvenanceMisrejectionRepair` variant's doc is specific: a rejection
   "contradicted by a `ProvenanceVerified` on the same stream". This repair is
   a different fact about a different population, and an audit query must be
   able to separate them. Follow that variant's doc discipline — say what
   happened and what it is distinct from.
5. **The dry-run report is the deliverable, not a courtesy.** It must state
   the exact population it would touch (count, and the per-repository
   breakdown), because that number is what the human needs before item 294
   changes any answer in production. Report the cap rather than applying it
   silently, exactly as the existing path does.

## Explicitly out of scope

- **The 6,206 merely-*held* signature payloads.** Those are not rejected;
  once 291 is in effect the ordinary release sweep clears them on its next
  tick with no repair at all. If an implementation finds itself writing a
  repair for a `Quarantined` row, 291 is incomplete — stop and say so.
- Any widening of `re_evaluate`'s eligibility guard (ADR 0041 #6(a)).
- Making the repair automatic, scheduled, or reachable by a service account.
- A migration that writes a status. The status is a projection of the stream;
  a repaired row gets there by an appended event or not at all (ADR 0039 D6).

## Acceptance

- A rejected `{}` config blob and a rejected signature payload, both with no
  `ProvenanceVerified` on the stream, are repaired to `Quarantined` with the
  original anchor, and released by the next sweep tick **with 291 in effect**.
- The same two rows are **refused** with 291's predicate inverted (i.e. a
  rejected *ordinary* layer with no terminal event is not in range) — show it
  red, do not assert it.
- A rejected artifact **with** an `ArtifactRejected` on its stream stays
  rejected under both authorities (conjunct 2 still load-bearing), and so does
  a corruption tombstone.
- Dry-run is the default at the HTTP edge and the mutating call is the opt-in;
  a dry-run writes no event, which is asserted against the event store, not
  inferred from the response body.
- The two repair authorities are distinguishable on the stream and in the
  response; one audit query separates them.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p <the crates this unit touches>` — check, fmt,
  clippy and those crates' tests, with a full per-step log under
  `handover/gatelogs/`. Judge by the output, not the rc. Do **not** run
  `cargo test --workspace`, `cargo audit`, `cargo deny` or the attribution
  script: together they take 15–25 minutes, longer than a worker's foreground
  tool window, and a backgrounded gate is killed and takes the report with it.
  The architect runs the full gate on the same tree before any MR; a red
  workspace-wide step becomes a new directive, not an in-run fix.
