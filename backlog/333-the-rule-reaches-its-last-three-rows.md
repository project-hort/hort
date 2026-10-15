# 333 — The rule reaches its last three rows

**Issue:** #350 · **Branch:** `agent/350-terminality-only-from-disproof`
**Governing decisions:** ADR 0039 D4 · ADR 0027 (the trust-root boot contract) ·
ADR 0007 (fail-closed).

**Depends on items 328 and 329.** Units 328 and 329 found these while applying
the rule and correctly left them alone — none was in their tables, and the
third needs a vocabulary decision the implementer was right not to take
alone. They are added here rather than carved out of item 330's amendment,
because an amendment that says *"our own ability to check → hold"* while three
of those cases still reject would be defending the gap instead of closing it.

## Row 1 — a trust root with no Fulcio certs rejects every artifact in the scope

`verify_one` step 3 builds the offline verifier from the cached trust root. A
root carrying no Fulcio certificates / CTFE keys cannot build one, and the
existing comment is explicit that the well-formed bundle then becomes
`CertChainInvalid` *"(not malformed)"*
(`crates/hort-adapters-provenance-sigstore/src/verifier.rs`, the `make_verifier`
step).

That is the **same class** as `NoMatchingRekorKey`, which item 328 just moved
to a hold: our provisioning failed, the publisher's chain was never examined,
nothing about the artifact was proved. It must become
`Indeterminate(TrustRootUnusable)`.

**And it needs the boot assertion its sibling already has.** `composition.rs`
asserts a non-empty Rekor key map at worker start but never that the root
carries Fulcio certs, so a root missing them boots cleanly and then condemns
every artifact in scope. Converting the verdict to a hold makes that assertion
*more* necessary, not less: a scope-wide silent stall with nothing terminal to
point at is harder to notice than a wave of rejections. Add the symmetric
assertion, with the same message shape unit 328 gave the Rekor one.

Three tests currently pin `CertChainInvalid` from the empty-root fixture
factory and will need their verdicts restated — name them in the report rather
than quietly editing them.

## Row 2 — a negative `tree_size` wears the one variant that condemns

`build_model_proof` maps the `i64 → u64` narrowing failure to
`InclusionError::VerifyFailed` (`inclusion.rs`, pinned by
`negative_tree_size_fails_closed`). After item 328, `VerifyFailed` is the
**only** variant in that enum classified `Disproof` — it means *"a proof we
read, and the cryptography said no"*. A negative tree size is nothing of the
kind: it is the bundle's own material being structurally absurd, in the same
family as `HashWidth` and `CheckpointParse`, both of which skip.

Give it its own variant (`TreeSizeInvalid`, or whatever reads best beside its
neighbours), classified `NothingProved`. The classification match is
wildcard-free, so the compiler will find every site.

Narrow, and worth saying how narrow so nobody over-weights it: it needs the
signer's own log entry to claim a negative tree size on a bundle that already
passed full Fulcio and signature verification. It is a hole in the rule rather
than a reachable attack.

## Row 3 — a verifier that returns `Err` terminally rejects, on a reason its rustdoc forbids

Unit 329 removed the fetch path's terminal rejection and then found the same
defect a few lines away. `ProvenanceOrchestrationUseCase::dispatch_and_fold`
still answers a verifier adapter's `Err` with:

```rust
ProvenanceMode::Required => ProvenanceVerdict::rejected(ProvenanceRejectReason::RekorNotFound)
```

An adapter that errored proved nothing about the artifact — this is
terminality without disproof, minted on the one reason whose rustdoc says it
is established *"cryptographically and fully offline"*. It is reachable by any
adapter `Err`, including a trust root that cannot build a verifier at all and
a subject-payload/content-hash mismatch.

**It needs a third `IndeterminateReason`, and that is why unit 329 stopped.**
Each existing reason would be a lie: `AttestationFetchFailed` says the
material was never obtained, when here it was fetched and read; and
`TrustRootUnusable` names one cause of an adapter `Err` rather than the
category. Reusing either would reproduce exactly the fault 329 removed.
Letting an errored verifier contribute *nothing* is also wrong — an
all-verifiers-errored run would fold to `NoAttestation`, reporting
`held_pending_signature` and sending the operator to their signer for **our**
adapter fault.

So: a third variant (`VerifierUnavailable`, or whatever reads best beside its
two neighbours), with the `held_` / `allowed_` reporting it inherits for free
from unit 329's `NoEventReport`. The mode `match` in `dispatch_and_fold` goes
the same way the one in `apply_fetch_failure` did — the epistemic state does
not depend on the mode.

**Two pieces of drift in the same function, to fix while you are there:** its
rustdoc fold ladder still reads *"else `NoAttestation` (no verifier found a
bundle)"* and omits the `Indeterminate` rung item 327 added to `fold_two`; and
its "degrade-to-allow" comment describes the behaviour this row replaces.

**One assertion becomes writable** once this lands, and unit 329 could not
honestly write it: that the **orchestration** constructs
`ProvenanceRejectReason::RekorNotFound` nowhere at all, leaving the keyless
verifier as its only producer. Add it as a counter-assertion.

## Acceptance

- A trust root with no Fulcio certs ⇒ the artifact **holds** with the
  trust-root reason, and no `ArtifactRejected` is appended.
- A verifier returning `Err` under `Required` ⇒ the artifact **holds** under
  the new reason, and under `VerifyIfPresent` it is allowed and **releases**
  on its window — one test per mode, each asserting the eventual state, the
  shape unit 329 established.
- The orchestration constructs `RekorNotFound` nowhere; pinned by a
  counter-assertion, not a grep.
- The worker refuses to boot with such a root, by the same assertion shape as
  the Rekor key map.
- `TreeSizeInvalid` skips; `VerifyFailed` still terminalises.
- `InclusionError::side()` stays wildcard-free and its table test still covers
  every variant with all three answers used.
- The three empty-root fixture tests have their new verdicts stated in the
  report, not silently edited.
- Full gate green. No issue/MR references in code comments.

## Out of scope

- Any other `CertChainInvalid` producer. The non-malformed `VE::Certificate`
  and non-transparency `VE::Signature` arms are findings about material that
  was read, and they stay terminal.
