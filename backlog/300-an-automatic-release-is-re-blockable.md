# 300 — An automatically released artifact is re-blockable; an explicitly released one is not

**Issue:** #344 · **Branch:** `agent/344-scan-verdict-release-authority`
**Governing decisions:** ADR 0007, ADR 0041 (invariant #6 and the
re-judgement model). **Touches both** — the amendment is discussed before it is
written; do not write ADR text in this item unless the architect hands you the
confirmed version.

**Depends on items 297–299** for the verdict and the authority; independent of
them in mechanism.

## What is true today

`Artifact::reject_from_scan`
(`crates/hort-domain/src/entities/artifact.rs:609`) refuses **every**
`Released` source state, and its doc gives the reason:

> Rejects `Released` (the operator already completed review; re-rejecting must
> go through retroactive curation or admin release-then-re-evaluation)

The rescan orchestration then books that refusal as *"already terminal"*,
records the fresh findings and **discards the rejection**
(`crates/hort-app/src/use_cases/quarantine_use_case.rs:683`–`:700`).

So a released artifact is never re-blocked by a scan, whatever the scan finds.
**The guard is broader than its own stated reason:** "the operator already
completed review" is true of an Admin or Curator release and false of a timer
release, which no operator reviewed.

Two consequences, both measured on #342: a scan that newly finds a CRITICAL in
a released artifact cannot act on it; and the 54-day window in which the
scanner recorded nothing (#264, fixed in 0.14.0) cannot be cleaned up by
rescanning, because every artifact in it is `Released`.

## The specification (Tom, 2026-10-10)

> Bringen nachfolgende Scans Findings oberhalb der Schwelle, wird das Artefakt
> wieder blockiert. **Ausnahme:** ein Admin/Curator hat eine explizite Freigabe
> eingestellt — das überwiegt jedes Scan-Ergebnis. Artefakte, die automatisch
> freigegeben wurden, werden bei Scanergebnis oberhalb der Schwelle blockiert.

## What to build

1. **The distinction needs no new data.** `ArtifactReleased` carries
   `released_by: ReleaseReason`
   (`crates/hort-domain/src/events/artifact_events.rs:511`), and the four
   values are exactly the partition:
   - `Timer`, `PolicyReEvaluation` ⇒ **automatic** ⇒ re-blockable;
   - `Admin`, `Curator` ⇒ **explicit human release** ⇒ protected, outweighs any
     later scan verdict.
   `PolicyReEvaluation` counts as automatic deliberately: the policy did not
   absolve the artifact, it re-judged it under the evidence of the day. Record
   that reasoning where the partition is written.
2. **Resolve the fact in the application layer, hand it to the domain.** The
   latest `ArtifactReleased` on the artifact's stream is a stream fact, so it
   follows the shape this codebase already uses for cross-axis preconditions —
   `ProvenanceClearance`, `CurationClearance`, `TerminalRejectionRecord`: the
   app layer reads it, the domain receives a verified value and stays pure. Do
   **not** have the domain reach for the stream.
3. **Narrow the source-state guard, do not remove it.** `Released` becomes
   admissible **iff** the prior release was automatic. `Rejected` stays refused
   (terminal), `Quarantined` and `None` keep their current behaviour, and the
   doc comment is rewritten to state the narrowed rule **and** why the guard
   existed — the Admin/Curator case it was always really protecting.
4. **The rescan orchestration stops discarding the rejection** for the
   re-blockable case, and keeps discarding it for the protected one — with the
   existing `debug!` distinguishing the two, because an operator reading the log
   must be able to tell "not re-blocked because a human released it" from "not
   re-blocked because it was already terminal".
5. **No new event, no new metric, no new operator surface.** The re-block emits
   the `ArtifactRejected` the scan axis already emits.

## Explicitly out of scope

- Cleaning up the 54-day window. That is an operator action; this item only
  makes a single rescan sufficient for it, and the report should say so without
  initiating anything.
- Curation and provenance re-blocking. Their paths are unchanged.
- Any widening of who may release.

## Acceptance

- A `Timer`-released artifact whose next scan breaches the threshold is
  **blocked** — status `Rejected`, `ArtifactRejected` on the stream with the
  scanner reason.
- A `Curator`-released and an `Admin`-released artifact with the same scan are
  **not** blocked, and the log says which of the two reasons applied.
- A `PolicyReEvaluation`-released artifact is blocked (the deliberate reading;
  if this acceptance is wrong, the partition is wrong, so flag it rather than
  adjusting the test).
- A `Rejected` artifact is still refused, and a `Quarantined` one still
  transitions as today.
- The domain takes the release-origin as a parameter and performs no stream
  read: assert it structurally (the entity's signature), not by inspection.
- Non-vacuity: invert the partition (`Admin` re-blockable, `Timer` protected)
  and show the first two tests red; restore.
- Gate: full local gate, one-shot capture, foreground, report before exit.
