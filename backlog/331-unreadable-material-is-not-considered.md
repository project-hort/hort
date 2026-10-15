# 331 — Unreadable material is not considered

**Issue:** #350 · **Branch:** `agent/350-terminality-only-from-disproof`
**Governing decisions:** ADR 0039 D4 (terminality only from positive disproof) ·
ADR 0039 §6 (the OR fold and the shape partition) · ADR 0007 (fail-closed) ·
ADR 0008.

**Depends on item 327** for the outcome vocabulary; independent of 328 and 329.
**Sequence it first among the verdict changes** — it is the one that closes the
exposure for material already in the tree, which no push-time check can reach.

## The maintainer's decision (#350, 2026-10-14)

> *"Wir müssen unlesbaren Müll idealerweise direkt ablehnen, so dass es
> garnicht in Betracht gezogen werden kann. Wenn das nicht verhindert werden
> kann, darf es trotzdem nicht berücksichtigt werden."*

Two rules. Item 332 is the door. **This item is the second rule:** material that
cannot be read contributes **nothing** to the verdict — it is not a rejection,
not a hold, not evidence of any kind. It is skipped, exactly as a non-cosign
referrer already is.

The two are not redundant. The manifest push resolves each layer's **row**, not
its bytes (`crates/hort-http-oci/src/manifests_write.rs`, module docs step 4 —
`find_by_checksum` plus a same-repo, non-terminal check, answered with 400
`MANIFEST_BLOB_UNKNOWN` at step 7). A row can exist while CAS does not hold the
bytes, so the door cannot always be certain. And nothing reaches referrers that
are already in the tree, or that Hort lands itself from an upstream proxy.

## What is true today

`verify_bundles` (`crates/hort-adapters-provenance-sigstore/src/verifier.rs:100-136`)
already has the concept this item needs. A bundle belonging to the *other*
backend is skipped outright:

```rust
if bundle.signature.is_some() {
    continue;
}
```

It contributes nothing — it does not verify, and it does not set `best`. The
gathering site says the same about a referrer with no signature material at all:
*"A referrer that carries neither … contributes nothing: skipped, not errored"*
(`crates/hort-app/src/use_cases/provenance_orchestration.rs:775-783`). An
attached SBOM does not reject anyone's image.

What is missing is that **unreadable** material does not get the same treatment.
`verify_one` (`verifier.rs:191-212`) answers four early gates with
`BundleVerify::Rejected(BundleMalformed)` — unparseable bundle JSON, no leaf
certificate, an undecodable certificate, an unreadable identity — and each of
those four comments already says the verifier *cannot make a decision* on the
input. A verdict is then made from it anyway, and `fold_two`'s unconditional
`Rejected ⊳ Verified` carries it over a real signature.

## What this item changes

**The four gates become skips, not verdicts.** An input the verifier cannot
read is `continue`d in the same loop position as a foreign-shape bundle. It
never reaches `merge_reason`, never becomes `best`, never folds. If every
candidate was skipped and none verified, the verifier returns `NoAttestation` —
*"I have nothing to say about this artifact"* — which under `Required` is the
indefinite hold D1 already defines, and under `VerifyIfPresent` is the allow it
already defines. No new state, no new branch; this is the one case in this
issue where the correct concept **removes** code.

The same applies to `map_verification_error`'s unreadable arms
(`verifier.rs:341-374`): `VE::Bundle(_)`, `VE::Input(_)` and the
`"malformed"`-flavoured `VE::Certificate(_)` are inputs the verifier could not
read. They skip. `VE::Certificate(_)` otherwise, `VE::Signature(_)` and
`VE::Policy(_)` are findings about readable material and keep rejecting.

The keyed adapter gets the same treatment for its `KeyedOutcome::Malformed`
(`crates/hort-adapters-provenance-cosign-key/src/lib.rs:205-224`): a
structurally broken payload or signature is skipped. `saw_digest_mismatch` and
`saw_wrong_key` are findings about readable material and stay terminal — see
item 328 for the `DigestMismatch` variant.

**`ProvenanceRejectReason::BundleMalformed` therefore loses every production
producer.** Keep the variant: persisted `ProvenanceRejected` events carry it and
must keep deserialising, exactly like `Unsigned`, whose rustdoc already records
the same situation (`crates/hort-domain/src/ports/provenance.rs:160-168`) —
copy that note's shape.

### Skipping is not silence

A skipped candidate must be **recorded**, or two real cases become
undiagnosable: a publisher whose own signature is broken would see only
"unsigned", and an operator would never learn that someone attached garbage to
an image. Carry a count of skipped-unreadable candidates out of the verifier
and surface it where the verdict is already surfaced — the `provenance-verify`
job's `result_summary`, the log line, and a metric label. The rule is *not
considered*, not *not noticed*.

## What this closes

S10-1 in full, for material already in the tree as well as new material. A
caller with write access attaches bytes declared as a Sigstore bundle; the
keyless verifier cannot read them and skips them; the keyed verifier verifies
the publisher's real signature; the fold sees `Verified` and `NoAttestation` and
answers `Verified`. The image serves. The garbage is reported and ignored —
which is the DKIM posture (*a broken signature counts as absent, never as
evidence against the message*) and, as far as I know, cosign's own (*at least
one attached signature satisfying the policy is a pass*). **Both of those are
from memory and must be read before item 330 cites them in the ADR.**

## Acceptance

- The headline test: a valid keyed bundle plus unparseable bytes declared as a
  keyless bundle folds to `Verified`, and the artifact is **not** `Rejected`.
- A test: unreadable material **alone**, under `Required`, yields the indefinite
  unsigned hold — not a rejection, and not a release.
- A test: unreadable material alone under `VerifyIfPresent` behaves exactly as
  an unsigned artifact does today.
- A test that the skip is **counted and surfaced**: the job's `result_summary`
  names how many candidates were skipped as unreadable.
- The existing adapter tests `malformed_bundle_is_rejected_bundle_malformed`
  (`lib.rs:295`) and
  `mixed_keyed_and_malformed_keyless_skips_keyed_keeps_keyless_reject`
  (`lib.rs:335`) **change meaning and must be rewritten, not deleted.** The
  second one's comment — *"the keyed bundle is skipped, but the malformed
  KEYLESS bundle still drives the verdict"* — states exactly the behaviour this
  item reverses; replace it with the new rule and say why in the report.
- A deserialisation test: a persisted `ProvenanceRejected` carrying
  `BundleMalformed` still loads.
- Full gate green. No issue/MR references in code comments.

## Out of scope

- The push-time refusal (item 332).
- Findings about readable material — wrong key, untrusted identity, broken
  chain, failed inclusion proof, digest mismatch. All stay terminal.
- Standing: *who* attached the material. Discussed on #350 and not chosen —
  this item makes authorship irrelevant for unreadable input rather than
  gating on it.
