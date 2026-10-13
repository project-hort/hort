# 315 — The signature-material clearance needs a trigger at both ends

**Issue:** #342 · **Branch:** `agent/342-referenced-blob-deliverability`
**Governing decisions:** ADR 0039 §11 (the two-ended cascade), §12 (every
standing cross-artifact lifecycle dependency names a trigger at **both** ends),
D8 (unit 291), ADR 0007 (fail-closed holds).
**Why this unit exists:** unit 291 built the rule and the architect's own
premise about how it would be reached was **wrong**. Measured, not argued.

## What is true today, after unit 291

D8's resolution lives in the constituent's own provenance verify
(`ProvenanceCascade::resolve_signature_material_clearance`, reached from
`verify_artifact` in the `NoAttestation × Required` window). It is correct and
its security proof is a test. **But almost nothing enqueues that verify for
this population**, so the rule is close to inert:

- The release sweep's expiry backstop **deliberately skips** the re-enqueue
  when `is_parent_gated_blob_constituent(&refs)` is true
  (`quarantine_use_case.rs`, the `summary.held_parent_gated` arm;
  `referenced_descendant.rs`). A cosign signature's `{}` config blob and
  payload layer have exactly that edge set, so they fall in the skip. Its
  comment states the rationale: *"a parent-gated blob is a STRUCTURAL hold
  (only the parent's cascade can lift it)"*. **D8 makes that false for this
  one population** — the parent's clearance now exists, but it is computed in
  the constituent's verify, which the skip prevents from ever running again.
- `ingest_signature_manifest` enqueues a verify for the **subject** only, not
  for the landed manifest's own constituents.
- So the only verify these rows ever get is the blob's own ingest-time one,
  which is enqueued **before** the manifest PUT (cosign uploads blobs, then
  PUTs the manifest). Whether the clearance resolves is therefore a race
  against job-dispatcher latency, and a verify that loses it has no second
  chance.

Consequences, both of which this unit closes:

1. **The 6,206 already-held signature payloads get no further verify at all**
   and stay held after 291 ships.
2. **The dependency is one-ended**, which ADR 0039 §12 exists to prevent.
   Unit 291 deliberately added no `DEPENDENCY_EDGES` entry rather than
   register a one-ended edge the guard would reject.

## What to do

### 1. The subject-end trigger — where the authority arrives

When a pure signature manifest lands through the §8 narrow signature ingest
(`ingest_signature_manifest`), enqueue a `provenance-verify` for **its own
constituents** — the config and layer digests named by its bytes, resolved to
artifact rows in the same repository — in addition to the existing
subject enqueue.

This is the end §11 already has for a signed subject, transposed to the
artifact that actually carries the authority: for D8 the authority is the
signature manifest, and the moment it lands is the moment its constituents
become clearable. It also removes the race in the paragraph above: the
clearance no longer depends on which job the dispatcher happens to pick first.

Fail closed and best-effort, exactly like the enqueues beside it: a digest
with no artifact row yet, or a failed enqueue, must not fail the ingest — the
constituent simply keeps its hold.

### 2. The backstop narrowing — how the already-held rows are reached

The expiry backstop's parent-gated skip must stop suppressing the enqueue when
a nominating parent is signature material. **Decide it on the parent's artifact
row, not on its bytes:** §8's narrow signature ingest lands a signature /
referrer manifest with `quarantine_status = None`, so "at least one nominating
parent has status `None`" is a cheap row-level test that needs no CAS read in
the sweep.

That test is a **proxy, and deliberately not authority**. It decides only
whether a verify is *enqueued*; whether the constituent is *cleared* stays
with D8's resolution, which reads the parent's bytes, classifies them and
requires the verifier to accept the bundle. A false positive therefore costs
one pointless verify; a false negative leaves a hold. Write that reasoning at
the predicate — a future reader must not mistake the proxy for the rule.

Keep the skip for every other parent-gated blob: an ordinary image layer under
a held parent still has no reachable verdict of its own, which is why the skip
was added and that reason is untouched.

### 3. The registry entry (ADR 0039 §12)

With both ends in place, register D8 as **its own** `DEPENDENCY_EDGES` entry,
not as a widening of `provenance_subject_constituent_clearance`. The
architect's reason, to be restated in the entry: the authority is a
**different artifact** — the signature manifest that verified the subject, not
the signed subject whose bytes bind its own constituents. Two dependencies
with different authorities that happen to share a direction are two edges; one
entry would make the registry lie about which artifact lifts the hold.

`every_registered_edge_is_two_ended` must pass with real code sites on both
ends (the ingest trigger from §1, the constituent verify from unit 291).

## Explicitly out of scope

- **Any repair pass.** With §2 in place the sweep reaches the held population
  on its own; a one-off migration would be a second instrument for a problem
  the sweep now solves. (The **rejected** population remains item 292.)
- **Caching the D8 verification.** Still a second authority.
- **A shape gate on the `NoAttestation × Required` arm.** Unit 291's F5 noted
  the resolution runs for every such artifact; D3 deleted the shape predicates
  on that arm and this unit does not reintroduce one. §1 reduces pointless
  verifies at the source, which is the right lever.

## Acceptance

- **The already-held case, through the sweep's own gate**: a `{}` config blob
  and a signature payload that are held, past their window, with their
  signature manifest already landed and the subject verifiable, are released
  by a sweep tick — proven through the sweep, not by calling the resolution
  directly.
- **The skip still holds where it should**: an ordinary image layer under a
  held *image* manifest gets no verify enqueued from the backstop, and the
  `held_parent_gated` counter still counts it.
- **The ingest trigger**: landing a pure signature manifest enqueues a verify
  for each of its constituents that has an artifact row, and none for digests
  that do not; a failed enqueue does not fail the ingest.
- **Two-endedness**: the registry entry exists, names both code sites, and
  `every_registered_edge_is_two_ended` passes. Show the guard red when either
  end is removed.
- **No tracker references in code comments.**
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p <the crates this unit touches>` — check, fmt,
  clippy and those crates' tests, with a full per-step log under
  `handover/gatelogs/`. Judge by the output, not the rc. Do **not** run
  `cargo test --workspace`, `cargo audit`, `cargo deny` or the attribution
  script; the architect runs the full gate on this tree before any MR.

## Line numbers

Measure every position yourself on this branch: unit 291 moved
`provenance_orchestration.rs` and `provenance_cascade.rs` substantially
(+131 / +450), and `quarantine_use_case.rs` has not been touched by this
issue at all yet.
