# 347 — The repair reaches a rejection that could never be terminal

**Issue:** #359 · **Branch:** `agent/359-repair-reaches-unsigned`
**Governing decisions:** ADR 0039 **D1** (a statement about a point in time
may never be terminal) · ADR 0039 **D6** (a terminal status with no terminal
event is an illegal state) · ADR 0041 #6(a) (a scan re-judgement never clears
a provenance rejection) · ADR 0007 (the release predicate the sweep applies
afterwards) · ADR 0038 (service accounts are strictly non-admin — the admin
gate is unchanged).

## What is true today

`ProvenanceMisrejectionRepairUseCase`
(`crates/hort-app/src/use_cases/provenance_misrejection_repair.rs`) is the
only exit from the terminal state the pre-D1 provenance arm produced. Its
predicate is three conjuncts, evaluated at `:312`, `:325` and `:331`:

1. `quarantine_status == Rejected`;
2. `TerminalRejectionRecord::from_events(...) == Absent` — nothing terminal on
   the stream, with `CorruptionTombstone` classified out separately;
3. `provenance_clearance_from(persisted, ProvenanceMode::Required) ==
   ProvenanceClearance::Cleared` — **a `ProvenanceVerified` is on the
   stream.**

The resolved `provenance` is then handed to the domain as a verified fact:
`Artifact::repair_provenance_misrejection(terminal_record, provenance, now)`
(`crates/hort-domain/src/entities/artifact.rs:1967`), which re-checks it.

## Why conjunct 3 is too narrow

It was chosen because it describes the **measured** population of #241, where
the signature landed 5.1 s after the rejection. It does not describe the
boundary of the defect.

A descriptor that *is* a signature's own config — the
`application/vnd.oci.empty.v1+json` empty object,
`sha256:44136fa3…` — never receives a signature of its own. Conjunct 3's
proof can therefore never arrive for it, and six such rows (measured on a
deployed instance: `reason = Unsigned`, `backend = (policy)`, no
`ArtifactRejected`, created 2026-07-04 … 2026-08-09) are stranded with no
exit at all.

ADR 0039 **D1** already settles their status: `ProvenanceRejected{Unsigned}`
is a statement about *a point in time* and may **never** be terminal. Only a
positive disproof — a signature that is *present* and invalid — may be.

**The population cannot grow.** `ProvenanceRejectReason::Unsigned`
(`crates/hort-domain/src/ports/provenance.rs:184-192`) says so in the tree:
*"No producer remains. The `Required`-mode policy mapping that emitted it was
removed by ADR 0039's 2026-09-12 amendment (D1 …), and no verifier produces
it."* The variant survives only so persisted events keep deserialising.

## What to build

**Conjunct 3 becomes a disjunction**, and the fact handed to the domain stops
being a bare `ProvenanceClearance`.

### The domain's third parameter

`repair_provenance_misrejection` currently takes `provenance:
ProvenanceClearance` and refuses anything but `Cleared`, with the stated
reason *"Without this an artifact that really was never signed would be
released."* That parameter should become a two-variant value naming **why
this terminalisation is structurally invalid** — the names are yours:

- **the stream contradicts it** — a `ProvenanceVerified` is on the stream.
  Resolved exactly as today, via `read_path_provenance_clearance` with
  `ProvenanceMode::Required` passed literally.
- **the verdict was of a kind that may never be terminal** — the only
  provenance verdict on the stream is a `ProvenanceRejected` whose
  `reason` is `Unsigned`.

The domain keeps re-checking the value it is handed; the application layer
keeps resolving the stream facts. The shape of the contract does not change,
only what counts as a proof.

### Why the doc comment's warning no longer applies to the second arm

*"Without this an artifact that really was never signed would be released"*
was true when the clearance was the only thing between the repair and a
release. It is not true of the second arm, for a reason the method's own
*"Why `Quarantined` and not `Released`"* paragraph already gives:

**the exit is `Rejected → Quarantined`, never `Released`.** The artifact lands
back in front of the ordinary release sweep with its original observation
anchor, and the sweep applies the **live** gates. For an artifact that really
was never signed on a `provenance_mode: required` repository, the live
provenance gate — post-D1 — **holds**. It does not release and it does not
re-reject. That is exactly D1's prescribed behaviour, and it is the sweep's
job, not the repair's.

So the safety of the second arm rests on conjuncts 1 + 2 (a terminal status
with no terminal event: D6's illegal state) plus the hold the sweep applies
afterwards. Say this in the doc comment, in place of the sentence it
replaces.

### Every narrowing, and why each one holds

- **Only `Unsigned`.** Every other `ProvenanceRejectReason` is a positive
  disproof — a signature that is present and wrong — and D1 permits those to
  be terminal. The second arm must key on the reason, not on the presence of
  a `ProvenanceRejected`.
- **Only when it is the *only* provenance verdict.** A stream carrying both
  an `Unsigned` and a later disproof is not this population.
- **Conjunct 2 is untouched.** A scan rejection writes `ArtifactRejected`; the
  historical corruption tombstone is classified out. Both still fall at
  conjunct 2 before conjunct 3 is reached.
- **`dry_run` stays the default** and the admin gate stays. Nothing about the
  route, its authority or its reporting changes.

## Acceptance

1. A row with `reason = Unsigned`, no `ArtifactRejected`, **no**
   `ProvenanceVerified` → listed by the dry run, and repaired by a real run
   to `Quarantined` with its original anchor.
2. A row with `reason = UntrustedIdentity` under the same other conditions →
   **not** listed, not repaired.
3. A row carrying `ArtifactRejected` → still not listed, whatever its
   provenance history.
4. The historical corruption tombstone → still refused, with its own message.
5. The `Cleared` arm is unchanged: the #241 shape is still listed and still
   repaired.
6. The emitted event is `ArtifactQuarantined` carrying the original
   observation anchor — never `ArtifactReleased`, and never a restarted
   window.
7. `dry_run` defaults to true, including on an absent body, and the dry run
   still consults the domain guard so it cannot report a set the real run
   would refuse.
8. **Counter-assertion.** A test pins that the second arm keys on the
   `reason` and not merely on a `ProvenanceRejected` being present —
   otherwise acceptance 2 silently becomes a pass-through and the narrowing
   that carries the whole decision is gone.
9. `hort-domain` and `hort-app` require **100% coverage**: every arm of the
   widened parameter, including the refusals.

## Out of scope

- The producer. Nothing emits `Unsigned` any more; this unit repairs a closed
  historical population and must not add a path that could create one.
- ADR 0062's mint-time rule. It stays exactly as it is; once the row is no
  longer terminal it has nothing to refuse.
- `curation reevaluate` and `waive`. Both correctly decline this population
  (ADR 0041 #6(a), and an axis that cannot be read); neither is widened here.
- Any change to the route, its admin gate or its report shape.
