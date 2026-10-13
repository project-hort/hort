# 291 — A signature manifest's own constituents are cleared by the signature that verified a subject

**Issue:** #342 · **Branch:** `agent/342-referenced-blob-deliverability`
**Governing decisions:** ADR 0039 (§8 signature classification, §11 clearance
cascade, D1 "a missing signature holds", D4 "terminality only from positive
disproof"), ADR 0027 (the provenance leg of the release gate), ADR 0007
(fail-closed holds). This unit **amends ADR 0039** with a `D8` — the wording is
in the issue description under *291 ergänzt ADR 0039 — der Wortlaut* and is
**confirmed** (human, 2026-10-12: authority variant **B**, the verifier's
verdict).

## What is true today, measured

Across the six repositories with `provenance_mode: required`, **not one**
signature payload is released — 6,206 `quarantined`, 2,639 `rejected`, 0
`released`; in the two repositories with `off`, all 231 are released. End to
end: the Referrers API answers 200, the signature manifest answers 200, and its
**payload answers 404 / 503**, with every byte present in the CAS.

Three facts decide the shape of the fix, and two of them corrected this item's
earlier premises:

1. **hort's own verifier is not blocked by the hold.**
   `ProvenanceOrchestrationUseCase::fetch_bundles_once` reads the payload with
   `cascade.read_bounded` → `storage.get` and never looks at
   `quarantine_status`. The hold blocks the **external** reader:
   `hort-http-oci/src/blobs.rs` matches on `artifact.quarantine_status`
   directly and answers 503 / 404. So the harm is that a third party cannot
   check the signature over content hort itself serves — not that hort cannot
   verify.
2. **The exemption already exists and stops at the manifest.** ADR 0039 §8
   exempts the signature *manifest* at the push path:
   `hort-http-oci/src/manifests_write.rs` tests
   `is_pure_sigstore_bundle || is_pure_simplesigning` and lands it through the
   narrow signature ingest (status `None`, no scan, the `oci_subject` edge).
   Its layers arrived earlier through the blob upload, where there is no
   manifest to classify, so the decision never reached them.
3. **A blob has one row and one status per hort repository.** The artifact path
   is `blobs/sha256:<hex>` with `UNIQUE (repository_id, path)` and **no OCI
   name component**, so whatever clears a blob clears it for every image in
   that repository. An exemption resolved from a *declaration* would therefore
   serve an unsigned layer to every consumer of the repository — which is the
   surface §8's purity requirement deliberately keeps closed on the scan axis
   ("gating on every *layer* being a bundle is the complete control").

Nothing signs a signature, so a signature manifest's own constituents — the
`{}` config blob and the payload layer — can never acquire an attestation of
their own. Under `Required` D1 holds them and D4 holds them *indefinitely*: a
hold no future evidence can end, which is the terminality D4 reserves for
positive disproof, reached by another route.

## What to do

**The clearance is a clearance, not an exemption.** The authority is the
verifier's verdict over the nominating manifest's own bundle, computed where
the verifier already is.

1. **Place it in the `NoAttestation × Required` window of
   `ProvenanceOrchestrationUseCase::verify_artifact`** — between
   `dispatch_and_fold` and `apply_verdict` (re-measure both; they were at
   `:618` and `:652` when this item was written). When the folded outcome is
   `NoAttestation` and the mode is `Required`, resolve the question below
   *before* the hold is applied. Everything needed is already in scope there:
   the applicable `ProvenancePort`s, the artifact, the CAS, and the
   content-reference index.

2. **The question, with its authority chain.** Is this artifact the signature
   material of a subject the verifier accepts?
   - Inbound `content_references` rows **nominate** candidate parents. They
     are a mutable projection and never authority — the cascade module's own
     doc says so and this unit does not weaken it.
   - For each candidate parent: read its bytes (`read_bounded`, the existing
     16 MiB `MAX_PROVENANCE_READ_BYTES`; a signature manifest is a few hundred
     bytes), classify with the §8 classifiers, and confirm **this artifact's
     own digest** is in the parent's constituent digest set — the config +
     layers walk `constituent_digests` already performs.
   - Resolve the parent's **subject from the parent's bytes**, not from the
     `oci_subject` edge: the manifest's `subject` descriptor. `hort-domain`'s
     `oci` module has no accessor for it yet — add the small pure one beside
     `manifest_blob_digests`, returning `Option<ContentHash>`, with the same
     error shape as its neighbours.
   - **Verify the parent's bundle against the subject's preimage** with the
     applicable port, exactly as `fetch_bundles_once` + `dispatch_and_fold`
     do for a subject's own verification. A success *is* the subject's
     verification, so it is the strongest statement available and it is not
     forgeable: a manifest shaped like a signature whose bundle does not
     verify yields nothing.

3. **On success, clear through the cascade's existing primitive**, with the
   signature manifest as the authority — the constituent gets a real
   `ProvenanceVerified` whose `cascaded_from` names that manifest. Do **not**
   replace the folded verdict with `Verified`: that would record a direct
   verification the artifact does not have, and it would send a blob down the
   direct-clearance cascade re-drive, which walks CAS bytes expecting a
   manifest. The cascade's membership rule today walks the *subject's* signed
   bytes; this is **one more membership rule in the same machinery** — the
   constituents of the signature that verified a subject — and it belongs
   beside the other two ends, not in a second module.

4. **Fail closed, everywhere.** A read error, a parse failure, a parent that
   is not a pure signature manifest, a parent whose subject cannot be
   resolved, a bundle that does not verify, or no candidate parent at all ⇒
   **no clearance**, and the artifact keeps exactly the hold it would have had.
   This mirrors the cascade module's standing posture: every failure is
   `warn!` + continue and never retracts or blocks a decision the caller
   already had.

5. **Nothing changes in `release_clearance.rs`, and that is the point.** Its
   provenance leg is `Cleared` iff **any** `ProvenanceVerified` exists on the
   artifact's stream, so a cascaded clearance releases the constituent through
   the gate that is already single-sourced. **No new `ProvenanceClearance`
   variant** — the earlier draft of this item asked for one to keep the case
   distinguishable from `NotRequired`, and the cascaded event distinguishes it
   better: the diagnostic names the signature manifest that cleared it
   (`cascaded_from`), not merely "not required".

6. **No new event field.** An optional `verified_by` on `ProvenanceVerified`
   was the agreed cost of authority variant B. It is **not needed**: the
   verification is computed at the point of use, so nothing has to be
   remembered — and a stored field would have been **worse**, because the
   6,206 rows already held carry verdicts written before the field existed and
   would have stayed held. (Had a field been added, #272's rule applies: an
   additive event field must be `#[serde(default, skip_serializing_if = …)]`,
   never a bare `#[serde(default)]`, or it changes the canonical bytes of
   every historical payload and breaks chain verification. `cascaded_from` in
   the same struct is the precedent.)

7. **The already-held population needs no repair instrument.** Those 6,206
   rows are held, so the release sweep re-attempts them and re-enqueues
   `provenance-verify` for them; the next run after this unit ships resolves
   the clearance and releases them. If anyone writes a repair pass for *held*
   signature payloads, this unit is incomplete — the rejected population is a
   different question and belongs to item 292.

8. **Amend ADR 0039 with D8** (text confirmed on the issue) and keep
   `docs/glossary.md`'s **Signature constituent** entry matching what the code
   does. Write the derivation at the mechanism, not only in the ADR: the
   resolution function's rustdoc states why edges nominate and bytes plus the
   verifier decide, and why a declaration cannot be the authority (fact 3
   above).

## Explicitly out of scope

- **The already-rejected population** (~2,639 payloads and six `{}` rows) —
  item 292, which is also the precondition for 294. This unit is
  forward-looking plus the held rows the sweep reaches on its own.
- **Whether `provenance_mode: required` applies to signature manifests
  themselves.** It does and stays so.
- **Any new operator knob.** The clearance is a property of the content and of
  a verifier verdict, never a setting.
- **Caching the verification.** The clearance is written once per row and the
  row then releases, so there is nothing to cache; a cache here would be a
  second authority.

## Acceptance

- **One definition, reached by every caller.** A scan of `crates/*/src` shows
  the signature-material resolution defined exactly once, inside the
  provenance verify path, with no second copy in `release_clearance.rs` or in
  a format crate. Name the call sites with counts in the report.
- **The positive case through the real gate**: a `{}` config blob and a
  signature payload under `provenance_mode: required` release **on the scan
  axis alone**, proven through the sweep's own gate — not through a test that
  calls the resolution function directly.
- **The decoy case** (this is the unit's security proof): a manifest that
  passes the §8 purity classifiers and names an ordinary layer as its
  constituent, whose bundle does **not** verify the subject, leaves that layer
  held. A test that cannot tell this population from the real one proves
  nothing; show it red when the verification step is removed.
- **The negative case**: an ordinary image layer under `required` with no
  signature anywhere still holds.
- **Fail-closed**, one test each: CAS read error, unparseable parent, parent
  that is not a signature bundle, unresolvable subject, verifier error.
- **The clearance is legible**: the constituent's `ProvenanceVerified` names
  the signature manifest in `cascaded_from`, and the log line at the clearance
  site carries both digests.
- ADR 0039 carries D8; the glossary entry matches the code.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p <the crates this unit touches>` — check, fmt,
  clippy and those crates' tests, with a full per-step log under
  `handover/gatelogs/`. Judge by the output, not the rc. Do **not** run
  `cargo test --workspace`, `cargo audit`, `cargo deny` or the attribution
  script: together they take 15–25 minutes, longer than a worker's foreground
  tool window, and a backgrounded gate is killed and takes the report with it.
  The architect runs the full gate on the same tree before any MR; a red
  workspace-wide step becomes a new directive, not an in-run fix.

## Line numbers

Every position above was measured on `agent/342-referenced-blob-deliverability`
rebased onto `develop` at `8728da40` (2026-10-12). Re-measure before you write:
`provenance_orchestration.rs` and `provenance_cascade.rs` both move with every
unit that touches them.
