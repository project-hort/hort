# 327 — The domain gains a state for "we could not check"

**Issue:** #350 · **Branch:** `agent/350-terminality-only-from-disproof`
**Governing decisions:** ADR 0039 D4 (terminality *only* from positive
disproof), D2 (fail-closed is not the same as terminal), D1 (absence of
evidence is not evidence of absence), D6 (the invariant that makes it
machine-checkable) · ADR 0039 §2 (the reject-reason mapping) · ADR 0007
(fail-closed) · ADR 0030 (expand/contract).

## The line, as the maintainer drew it

Confirmed on #350 (2026-10-14), over three exchanges:

1. **Option (b):** D4 applies as written — terminality only from positive
   disproof.
2. **Unreadable material is refused, and otherwise ignored:** *"Wir müssen
   unlesbaren Müll idealerweise direkt ablehnen, so dass es garnicht in
   Betracht gezogen werden kann. Wenn das nicht verhindert werden kann, darf es
   trotzdem nicht berücksichtigt werden."* Items 332 and 331 carry those two
   rules.

So nothing a verifier **could not read** produces a verdict at all, and the
question this item answers is what remains:

| the failure is about | verdict |
|---|---|
| readable material that failed — forged, wrong key, wrong digest, broken chain, failed inclusion proof | **terminal rejection** |
| material that could not be read | **no verdict at all** — skipped and recorded (item 331), or refused at push (item 332) |
| **our own** ability to check — no usable trust-root key, material we could not fetch | **hold**: this item |

The third row is what the domain cannot say today, and it is the whole of this
item. It is not an exception for an edge case: it is D4 applied to the case
where **nobody's material is at fault**. A publisher's artifact must not go
terminal because our trust root was misprovisioned or a network call failed.

## What is true today

`ProvenanceOutcome` (`crates/hort-domain/src/ports/provenance.rs:191-216`) has
`Verified`, `Rejected(ProvenanceRejectReason)` and `NoAttestation`. The hold
lives entirely in the third: `Artifact::complete_provenance` answers
`NoAttestation` with `Ok(Vec::new())` — no events, status left `Quarantined`,
and under `Required` the release gate reads `Pending` because no
`ProvenanceVerified` exists on the stream (`crates/hort-domain/src/entities/artifact.rs:1569`+,
pinned by `complete_provenance_no_attestation_always_holds_never_terminalises`,
`:4181`). `Rejected(_)` drives `quarantine_status = Rejected` plus
`ProvenanceRejected` + `ArtifactRejected`.

There is no way to say *"we could not check"*, so two sites say "proved bad"
instead — the fetch-failure path (item 329) and two `InclusionError` variants
(item 328).

### `BundleMalformed` is overloaded, and one half of it is a real finding

Read this before touching any mapping. The keyed adapter maps **the re-tag
attack** — a signature that verifies against a pinned key and covers a
*different* digest — onto `BundleMalformed`, the same variant as a structurally
broken bundle, and its comment says why:

> *"The re-tag attack + a structurally-broken payload/sig both map to
> `BundleMalformed`; a digest-binding failure is the priority reason (ADR 0039
> §2 reject-reason mapping — **no dedicated `DigestMismatch` variant**)"*
> (`crates/hort-adapters-provenance-cosign-key/src/lib.rs:218-224`)

ADR 0039 names digest-mismatch as a reject cause at `:128` and in the disproof
list at `:959`, but the vocabulary has no word for it, so the audit record
cannot tell a re-tag attack from a corrupt upload. Under item 331 the two
halves part company — the re-tag attack stays terminal, the corrupt upload
becomes a skip — so the variant is not optional: without it, separating them is
not expressible.

## What this item adds

### 1. One new outcome and one new reason type

```rust
/// Why a verification could not be carried out. **Our** side: nothing
/// about the artifact's material was established, so nothing was
/// disproved and the artifact is HELD, never rejected (ADR 0039 D4).
/// Material that WAS readable and failed is a `ProvenanceRejectReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndeterminateReason {
    /// Attestation material could not be obtained at all.
    AttestationFetchFailed,
    /// The trust root holds no usable key for this check — no Rekor key
    /// matches the entry's log id, or our own key bytes did not parse.
    /// An operator provisioning fault, not a finding about the artifact.
    TrustRootUnusable,
}
```

`ProvenanceOutcome` gains `Indeterminate(IndeterminateReason)`.
`Rejected(ProvenanceRejectReason)` is unchanged.

`ProvenanceRejectReason` keeps **every** existing variant — it is the wire
type on the `ProvenanceRejected` payload and persisted events carry all of
them — and gains `DigestMismatch`.

**The type is the enforcement.** An indeterminate reason cannot be constructed
as a rejection because `Rejected` does not accept it, and there is deliberately
**no** `From<IndeterminateReason> for ProvenanceRejectReason` — that conversion
is the one thing that would re-open the line. State that in the rustdoc so a
future reader does not add it as a convenience.

**No source-scan guard accompanies this.** The property is a compile error plus
wildcard-free matches, which force a future variant to be classified before it
can compile. A grep guard on top would imply the compile-time property is
insufficient; say so in the rustdoc.

### 2. The domain holds on `Indeterminate`

`complete_provenance` answers `Indeterminate(_)` with `Ok(Vec::new())` —
byte-identical to its `NoAttestation` arm. No status change, no event. Under
`Required` the release gate reads `Pending` (fail-closed, held); under
`VerifyIfPresent` / `Off` the artifact runs its normal quarantine window and
releases. Both fall out of "emit nothing" — the mode needs no branch, which is
exactly what `apply_verdict`'s own comment already says about the
`NoAttestation` pair: *"the domain produces the same (absent) transition for
both, and only the mode distinguishes them."*

The match must stay wildcard-free and its test must assert over all four
outcome shapes.

### 3. The fold: `Rejected ⊳ Verified ⊳ Indeterminate ⊳ NoAttestation`

`fold_two` (`crates/hort-app/src/use_cases/provenance_orchestration.rs:1506-1515`)
gains one position. `Verified ⊳ Indeterminate` says a real signature is not
overridden because the *other* verifier had no usable trust-root key — our
provisioning fault cannot invalidate a signature we did verify. `Rejected ⊳
Verified` is **unchanged**: a finding about pushed material still dominates,
which is the maintainer's decision.

`fold_two_backend` (`:1521-1530`) follows unchanged.

### 4. A third `HoldReason`

`HoldReason` (`provenance_orchestration.rs:221-231`) answers *"what is the
operator waiting for"*. The new answer is *"we could not check — fix the trust
root, or the fetch will be retried"*, which is a different operator action from
"sign it" and "push the parent". Carry it through all three mappings the type
deliberately keeps on one type: `metric_result`, `verdict_summary`,
`log_message`. The hold-reason resolution in `apply_verdict` (`:1294-1304`)
gains the `Indeterminate` case alongside `NoAttestation × Required`.

### 5. One paragraph the report must contain

`ProvenanceRejectReason` rides a persisted event payload, so adding
`DigestMismatch` is a forward-only vocabulary change: a **rollback** to a
release that predates the variant cannot deserialise an event carrying it.
That is the same class as adding a new `DomainEvent` type, not a new hazard —
but it must be a stated decision, not a side effect. Say in the report whether
the arm is accepted as forward-only (and why that matches existing practice)
or whether an unknown-variant fallback is added, and name the site either way.

## Acceptance

- No wildcard is added to any match over `ProvenanceOutcome`; every consumer
  states its answer.
- A domain test: `Indeterminate(_)` emits **no** events and leaves
  `quarantine_status` untouched, over every `IndeterminateReason` variant.
- A domain test: every `ProvenanceRejectReason` still terminalises, mirroring
  `complete_provenance_bad_signature_is_terminal_on_every_shape` (`:4249`),
  including the new `DigestMismatch`. `BundleMalformed` keeps terminalising
  **in the domain** — item 331 removes its producers, it does not change what
  the domain does with one.
- A fold test pinning all four precedences, including that `Rejected ⊳
  Verified` is unchanged.
- A deserialisation test loading a persisted `ProvenanceRejected` payload for
  every pre-existing variant. No migration, no DDL.
- **No production site constructs `Indeterminate` yet** — verdicts are
  byte-for-byte what they were. Items 328 and 329 move the two sites.
- Full gate green. No issue/MR references in code comments.

## Out of scope

- Which failures produce a rejection at all (items 331 and 332). This item
  adds the vocabulary and the hold; it moves no producer.
- `Retry-After` on the new hold — the open question on #314. The new hold takes
  exactly the shape the unsigned hold has today.
- Artifacts already `Rejected` from a past trust-root or fetch failure. A
  maintainer decision, recorded on #350; no sweep, no corrective event.
