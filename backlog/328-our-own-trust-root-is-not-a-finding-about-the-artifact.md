# 328 — Our own trust root is not a finding about the artifact

**Issue:** #350 · **Branch:** `agent/350-terminality-only-from-disproof`
**Governing decisions:** ADR 0039 D4 · ADR 0039 §2 (the reject-reason mapping
this item extends with `DigestMismatch`) · ADR 0007 (fail-closed) · ADR 0008.

**Depends on item 327.** Two changes, both small, both at adapter level.

## 1. Two of nine `InclusionError` variants are ours, not the publisher's

`crates/hort-adapters-provenance-sigstore/src/verifier.rs:255-268` folds all
nine `InclusionError` variants into one `RekorNotFound` rejection — and the
comment directly above says the distinction is real and is kept only in a
`debug!` line:

> *"The `InclusionError` variant distinguishes the fail-closed branch (e.g.
> `NoMatchingRekorKey` — **a trust-root misprovision** — vs `VerifyFailed` — a
> forged/non-included proof); it is recorded at `debug!` … so operators can
> tell those apart."*

Map it instead of logging it (`inclusion.rs:60-84`):

| `InclusionError` | whose side | verdict |
|---|---|---|
| `NoMatchingRekorKey` — no trust-root Rekor key matches the entry's log id | **ours** (provisioning) | `Indeterminate(TrustRootUnusable)` → **hold** |
| `KeyParse` — our trust-root key bytes did not parse | **ours** (provisioning) | `Indeterminate(TrustRootUnusable)` → **hold** |
| `VerifyFailed` — a present, readable proof that did not verify | the material, and something **was** proved | `RekorNotFound` → terminal, unchanged |
| `NoTlogEntry`, `NoInclusionProof`, `NoCheckpoint`, `CheckpointParse`, `HashWidth`, `NoLogId` — the bundle's own log material is absent or unparseable | the material, and **nothing** was proved | **skipped** (item 331's rule) |

**`VerifyFailed` is the only disproof in this enum.** That is the governing
sentence applied strictly: *only readable material from which something was
actually proved can condemn an artifact.* A bundle carrying no inclusion
proof — a v0.1-shaped bundle, say — is not garbage and not a forgery; it is
material nothing could be concluded from, so it contributes nothing and the
artifact holds as unsigned. An earlier draft of this item kept those six
terminal; that was written before the maintainer settled the rule on
2026-10-14 and is struck.

Note what still separates the two non-terminal groups, because it is the whole
value of keeping them apart: both end in a hold under `Required`, but the
trust-root rows hold **with a reason naming our provisioning** ("fix the trust
root"), while the six material rows hold as plain unsigned ("this artifact
carries no usable signature"). Same state, different operator action.

Why the two must move: a publisher pushes a correctly signed, log-included
artifact; the operator has not provisioned the matching Rekor key, or
provisioned a corrupt one. Today the artifact is terminally rejected. Nothing
about it was checked, so nothing was disproved — and the remedy is in the
operator's trust root, not in the artifact. That is D4's case exactly, with no
exception involved. Once the key is provisioned the held artifact verifies on
the next run; a terminal rejection would have needed a curator per artifact.

Write the match **wildcard-free** so a tenth variant must be classified, and
put the "whose side is this on?" question in the rustdoc as the test a future
variant has to answer.

## 2. The re-tag attack gets its own reason

`crates/hort-adapters-provenance-cosign-key/src/lib.rs:218-224`:

```rust
let reason = if saw_digest_mismatch || !saw_wrong_key {
    ProvenanceRejectReason::BundleMalformed
} else {
    ProvenanceRejectReason::UntrustedIdentity
};
```

- `saw_digest_mismatch` → **`DigestMismatch`** (terminal). Keep it as the
  priority reason; §2 says so (`:115`, `:128`).
- `saw_wrong_key` only → `UntrustedIdentity` (terminal, unchanged).
- neither — a structurally broken payload or signature
  (`KeyedOutcome::Malformed`) → **skipped**, per item 331.

**This item changes no verdict**; it gives the first case its own word.
Separating the three is what lets item 331 skip the third without taking the
re-tag attack with it. What changes is that the
`ProvenanceRejected` event can finally distinguish "someone re-tagged a signed
image" from "the upload is corrupt". Note the precedence the current expression
encodes by accident: `!saw_wrong_key` puts "malformed only" into the
digest-mismatch branch, so the three cases need separating even though their
verdict is identical.

## 3. The two folds that must agree

`verify_bundles` can now answer `Indeterminate`, so `BundleVerify` and
`merge_reason` (`verifier.rs:139-160`) grow a third case. The precedence inside
the verifier must be the same as item 327's fold: **any rejection outranks an
indeterminate** (a finding about the material beats "we could not check"), and
within the rejections the existing rank order is kept unchanged.

Leave one thing alone, deliberately, and expect one thing to have moved:

- **Leave alone:** `verify_bundles` returns `Verified` on the **first** bundle
  that verifies (`:112-122`). That is the intra-verifier answer to the same
  question item 327's fold answers across verifiers, and the two now agree.
- **Expect moved:** the fallback at `:135` was
  `best.unwrap_or(ProvenanceRejectReason::BundleMalformed)`. **Item 331 changes
  it**, because a verifier that read nothing has nothing to say — the answer
  there is `NoAttestation`, not a rejection. An earlier draft of this item told
  you to keep the old fallback; that instruction was written under a decision
  the maintainer superseded on 2026-10-14 and is struck. If you find the old
  form still in the tree when you start, item 331 did not land as specified —
  stop and report rather than restoring it.

## One sentence to delete when this lands

Unit 331 kept `ProvenanceRejectReason::BundleMalformed` and gave its rustdoc a
note in `Unsigned`'s shape — but deliberately **not** `Unsigned`'s sentence
*"No producer remains."*, because at that point the keyed verifier's
digest-binding failure still mapped to `BundleMalformed`. This item moves that
producer to `DigestMismatch`, which makes the variant genuinely producer-less.
The note's last sentence (the one naming the remaining producer) is then false
and must go. Check it rather than assuming its wording.

## Where this sits

Items 331 and 332 answer material the verifier **could not read**: it is
refused at push, and skipped if it got in anyway. This item answers the
neighbouring question — material we could not **check**, because our own trust
root had no usable key. Neither is a finding about the artifact, and the two
together leave exactly one thing able to condemn it: readable material from
which something was actually proved.

## Acceptance

- A test per `InclusionError` variant asserting its kind, wildcard-free.
- A test: a keyless bundle whose log id has no matching trust-root key ⇒ the
  artifact is **held**, no `ArtifactRejected`, and the hold reason names the
  trust root.
- A test: `VerifyFailed` still terminalises — the forged-proof case must not
  drift into the hold.
- A test pinning `DigestMismatch` is terminal, and one pinning that a
  malformed-only keyed set is **skipped** rather than rejected (item 331's
  rule; an earlier draft of this line said terminal and is struck).
- A test per non-terminal `InclusionError` row showing which of the two holds
  it produces — the trust-root hold names the trust root, the six material
  rows produce the plain unsigned hold.
- Every pre-existing provenance test either passes unchanged or has its new
  verdict stated in the report with the reason.
- Full gate green. No issue/MR references in code comments.

## Out of scope

- The orchestration's fetch-failure path (item 329).
- The ADR amendment (item 330).
- `is_pure_sigstore_bundle`'s media-type-only recognition, and any push-time
  validation of bundle bytes. Both were discussed on #350 and neither was
  chosen.
