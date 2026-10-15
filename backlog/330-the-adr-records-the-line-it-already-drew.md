# 330 — ADR 0039 records what can condemn an artifact

**Issue:** #350 · **Branch:** `agent/350-terminality-only-from-disproof`
**Governing decisions:** ADR 0039 (the document amended) · the project's ADR
discipline: a narrowing of a standing decision is an **amendment to that
decision**, never a new ADR and never a mechanism built around it.

**Depends on items 327, 328, 329, 331 and 332** — the amendment describes
shipped behaviour, so it lands last.

## The amendment, dated, in the same form as the 2026-09-12 one

### 1. One rule, four rows

Record the rule the five items establish, as one sentence plus the table it
decides:

> Only **readable material from which something was actually proved** can
> condemn an artifact.

| the failure is about | verdict |
|---|---|
| readable material that failed — forged, wrong key, wrong digest, broken chain, failed inclusion proof | terminal rejection |
| material that could not be read | **no verdict**: refused at push, and skipped if it got in anyway |
| our own ability to check — an unusable trust root (no matching Rekor key, unparseable key bytes, no Fulcio certs), material never fetched, **or a dispatched verifier that returned no verdict at all** | hold |
| no attestation at all | hold under `Required` (D1, unchanged) |

### 2. "Malformed" leaves the positive-disproof list — and the argument is not the one I first proposed

The 2026-09-12 amendment's closing section (`:959-961`) reads:

> *"**Positive disproof.** A forged, wrong-key, digest-mismatched or
> **malformed** signature still rejects terminally, on every shape — subject,
> constituent, descendant alike."*

Three of the four stay verbatim. **Malformed leaves**, and the reason must be
stated precisely, because the maintainer rejected the first version of this
argument before accepting a different one:

- It is **not** that a malformed signature is held instead of rejected. That
  was proposed and declined — tolerating garbage is not Hort's job.
- It is that **unreadable bytes are not a signature whose validity can be
  judged at all.** There is nothing to prove or disprove, so the material does
  not enter the evaluation: it is refused at the door, and ignored if it got in
  by another route.

Record both the declined and the accepted reading. A future reader who sees
only the conclusion will otherwise re-propose the declined one.

Record also what makes this safe rather than lax: Hort still refuses to serve
an artifact with no valid attestation under `Required` — ignoring unreadable
material produces the unsigned **hold**, never a release.

### 3. §6's "never a false-reject" becomes true

§6 (`:178-193`) promises *"never a false-reject"* and rests it on *"In practice
an artifact carries one signature shape"*. The promise was false in one
reachable case: a caller with **write access only** could attach bytes declared
as a Sigstore bundle to someone else's validly keyed-signed image and drive it
terminal. §6's own parenthetical (`:180-184`) shows the hazard was met once —
the `signature.is_some()` skip fixed the *well-formed keyed* case and left the
case of bytes that read as neither shape.

Record that the premise is now **held rather than assumed**: unreadable
material cannot contribute a verdict, so a second writer cannot manufacture
one. And record the inconsistency this removed, because it is the clearest
statement of the whole change: **inside** one verifier a verified bundle
already beat an unreadable sibling (`verify_bundles` returns on the first
bundle that verifies and skips foreign shapes, `verifier.rs:100-136`);
**across** two verifiers the unreadable sibling won. The two folds now agree.

### 4. The cross-domain precedent, read before it is cited

The posture — *a broken signature counts as absent, never as evidence against
the subject* — is the established one in email (DKIM, where anyone on the
delivery path may add a signature) and, as far as I know, in cosign itself
(at least one attached signature satisfying the policy is a pass). **Both of
those were stated from memory on #350 and must be read before this amendment
cites them.** RFC 6376 and the cosign documentation; if either does not say
what I recalled, drop the citation rather than soften it.

Record the counter-example too, because it is what makes the choice an argument
rather than a preference: **DNSSEC** deliberately treats a broken signature as
worse than none. That is right there and wrong here for one reason — in DNSSEC
only the zone owner can publish signatures, so no third party can plant a
broken one. Hard failure is safe while the signal can only come from the owner;
it becomes a weapon once strangers can write.

### 5. What this amendment does not change

- **The release gate.** No `ProvenanceVerified`, no clearance; `Pending` stays
  the fail-closed reading. No release authority is added or widened.
- **Disproof stays terminal** on every shape, for the three remaining causes.
- **The §8 push-path exemption** and its "every layer must be signature
  material" anti-scan-evasion rule. Item 332 adds a shape check *inside* the
  exemption; it does not widen it.
- **D5 and `Retry-After`** — the open question on the quarantine-deadline
  issue. Not answered here.
- **ADR 0016 is not triggered.** No operator opt-in is added and no new input
  reaches the release-gate computation.

### 5b. The third row is a category with three distinct causes

State it as such, because the distinction is the reason there are three
`IndeterminateReason` variants rather than one reused:
`TrustRootUnusable` (our provisioning — no matching Rekor key, unparseable
key bytes, or a root that cannot build a verifier at all),
`AttestationFetchFailed` (the material was never obtained), and
`VerifierUnavailable` (the verifier ran and returned no verdict). Collapsing
them would make the operator-facing hold reason less specific than the code
can be — each names a different thing to go and fix.

### 6. ADR 0027 carries five sentences this work falsifies

Unit 331 found these and correctly left them for this item. **ADR 0039 is not
the only document that describes the old behaviour**, so the amendment sweep
has to reach here too:

- `docs/adr/0027-artifact-provenance-verification.md:54-55` — *"as is a trust
  root carrying no Rekor public key (it would reject every bundle
  `RekorNotFound`)"*. Two things moved. There are now **two** boot refusals,
  not one — the second for a root that cannot build a verifier at all — and
  the parenthetical reason is false for both halves: each now **holds** every
  bundle rather than rejecting it, which makes the refusals more important,
  not less. The sentence should name both and give the hold as what they
  prevent.
- `:58` — *"A bundle lacking offline-verifiable material is
  `Rejected{BundleMalformed}`"*. It is now skipped and produces no verdict.
- `:75` — *"Any failure is fail-closed `Rejected{RekorNotFound}` (never a
  panic, skip, or live fetch)"*. There are now three answers, and absent or
  unparseable log material **is** a skip. The inclusion module's split is
  **1 disproof / 2 trust-root / 7 nothing-proved** — count it against the
  enum rather than copying that figure, which moves with every variant.
- `:151` — *"a forged 'bundle' is verification-inert (it can only produce
  `Rejected`/`BundleMalformed`, never `Verified`)"*. The **inertness claim
  survives and is now stronger** — it produces nothing at all rather than a
  rejection — but the parenthetical names a verdict that, after item 328, has
  no producer anywhere in the workspace.
- `:120` — *"Bundle-fetch exhaustion under `Required` fail-closes
  (`Rejected{RekorNotFound}`); under `VerifyIfPresent` it degrades to
  `NoAttestation` so infrastructure flakiness never blocks a proxy"*. Item
  **two** paths did this, not one: the bundle-fetch exhaustion the sentence
  names, and the verifier-error arm a few lines away in the same function
  (item 333 row 3). Both are gone, so the sentence's whole shape —
  "fail-closes under one mode, degrades under the other" — is wrong twice
  over, and `ProvenanceRejectReason::RekorNotFound` now has **no producer in
  `hort-app` at all** (its only remaining appearance there is the metric
  label mapping, which must stay — it still labels the verifier-produced
  reason). Item 329 made the fetch path one verdict in every mode —
  `Indeterminate{AttestationFetchFailed}` — with the mode deciding only the
  consequence: a hold under `Required`, allowed through (and reported as
  `allowed_indeterminate`, not `no_attestation`) under the permissive ones.
  **The fail-closed half still stands and should be restated, not dropped**:
  no `ProvenanceVerified` means `Pending` at the release gate, so a
  never-verified `Required` artifact still does not timer-release. The
  trailing `provenance_orchestration.rs:246` line reference is also stale.

Correct each in place, quoting the old text, and note in the ADR 0039
amendment that ADR 0027's descriptive text was brought along. Do **not** treat
this as a second decision: the decision is the one recorded on #350, and these
sentences are downstream description of it.

## Also in this item

- `docs/architecture/how-to/enable-provenance-verification.md` — its
  `result ∈ {verified, rejected, no_attestation}` line is stale and was
  already wrong by four values before this work began
  (`held_pending_signature`, `held_pending_subject`,
  `cleared_signature_material`, `requeued_no_anchor`). Unit 327 found it and
  correctly left it alone as unrelated drift; repair it here, where the
  vocabulary is being written down anyway. It is wrong by **six** now: item
  329 added `allowed_indeterminate` alongside 327's `held_indeterminate`, so
  the closed taxonomy is nine values and `docs/metrics-catalog.md` (already
  updated by those two items) is the list to copy. Check the rest of
  `docs/architecture/` for the same list.
- `docs/glossary.md` — "indeterminate provenance" is a new term and gets an
  entry saying plainly that it is **not** `ScanIndeterminate`: different axis,
  neither implies the other, only one of the two is terminal.
- The decision index (`docs/adr/0000-historical-decisions-index.md`) row for
  ADR 0039 gains the amendment date.

## Acceptance

- The amendment is dated, quotes every sentence it touches, and states for each
  whether it stands, is narrowed, or is now true where it was not.
- Every behavioural claim is true of the code **as merged by items 327–332**,
  with `file:line`.
- Every external citation (RFC 6376, cosign) was **read**, not recalled. Any
  that does not hold is dropped.
- `docs/glossary.md` distinguishes indeterminate provenance from
  `ScanIndeterminate`.
- Full gate green.
