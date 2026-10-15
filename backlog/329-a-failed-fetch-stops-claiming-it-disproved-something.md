# 329 — A failed fetch stops claiming it disproved something

**Issue:** #350 · **Branch:** `agent/350-terminality-only-from-disproof`
**Governing decisions:** ADR 0039 D4 (terminality only from positive
disproof), D2 (fail-closed is not the same as terminal), D8 (signature
material is not on the provenance axis) · ADR 0007 (fail-closed).

**Depends on item 327** (it needs `Indeterminate`); independent of item 328,
but sequence it after so the two hold-producing sites land in one reviewable
order.

This is the site the maintainer's option (b) was opened for, and the one where
nobody's material is at fault: a network error is not *"shit in"*.

## What is true today

`ProvenanceOrchestration::apply_fetch_failure`
(`crates/hort-app/src/use_cases/provenance_orchestration.rs:1451-1476`) writes
a **terminal** rejection when the attestation material could not be fetched at
all, and says so:

```rust
ProvenanceMode::Required => {
    tracing::warn!(…, "provenance: fetch exhausted under Required — fail-closed (RekorNotFound)");
    // `RekorNotFound` is the backend-AGNOSTIC fail-closed-fetch reason
    // here ("no verifiable attestation material was obtained"). The keyed
    // `cosign-key` backend has no Rekor, but reuses this marker rather than
    // growing the enum — the audit event's `backend` label disambiguates
    // which backend's fetch failed.
    let verdict = ProvenanceVerdict::rejected(ProvenanceRejectReason::RekorNotFound);
```

Two separate problems in one statement.

**It is terminality without disproof.** A fetch failure is weaker than "the
signature has not arrived yet" — it says *we could not look*. D4 allows
terminality *only* from positive disproof, and D2 already drew the distinction
on the neighbouring axis: fail-closed, yes; terminal, no.

**It mints a reason whose own documentation forbids this use.** The variant's
doc in `crates/hort-domain/src/ports/provenance.rs:171-180` says
`RekorNotFound` is established *"cryptographically and fully offline"* and is
**"never a fall-back to a live Rekor fetch"**. The orchestration contradicts
that sentence directly. The comment above even names the shortcut — *"reuses
this marker rather than growing the enum"* — so the record is accurate about
what was traded away. Item 327 grew the enum; the shortcut has no remaining
justification.

Since #345 the resulting terminal state is curator-correctable
(`is_curator_overridable` admits `RejectionReason::Provenance`,
`crates/hort-domain/src/entities/artifact.rs:2192`), so this is not
unreachable — but a per-artifact curator decision is not an operating
procedure for a network error.

## What this item changes

`apply_fetch_failure` returns
`ProvenanceOutcome::Indeterminate(IndeterminateReason::AttestationFetchFailed)`
and the **mode branch goes away**: the epistemic state is the same in every
mode, and the mode already decides the consequence downstream. Specifically,
with item 327 in place:

- Under `Required`: `complete_provenance` emits nothing, the artifact stays
  `Quarantined`, the release gate reads `Pending` (fail-closed) because no
  `ProvenanceVerified` exists on the stream — a hold, carrying the new
  `HoldReason` so the operator sees *why*.
- Under `VerifyIfPresent` / `Off`: `complete_provenance` emits nothing, so the
  artifact proceeds through its normal quarantine window and releases exactly
  as it does today. **This is the half that must be pinned by a test** — it is
  the one that could silently turn into a hold and strand every artifact in a
  permissive repository.

So one return value replaces a two-armed `match` on the mode. Removing that arm
is the point: the previous shape existed because the outcome vocabulary could
not express *"we could not look"*, and it answered the question twice — once by
rejecting and once by degrading.

Keep the `warn!` on both paths; correct its wording (it is no longer a
rejection) and keep the `stage` and `error` fields, which are the only record
of *which* fetch failed.

Then make the two pieces of prose true:

- The `RekorNotFound` rustdoc (`provenance.rs:171-180`) keeps its *"never a
  fall-back to a live Rekor fetch"* sentence, and after this item nothing
  contradicts it. Its wording also covers *"the tlog material is structurally
  absent / unparseable"*, which item 328 leaves terminal — so the doc needs one
  added sentence saying what the variant no longer covers: a fetch that never
  happened, and a trust root with no usable key.
- Collector entry E34 on the audit issue described this gap; the fix is this
  item. No code comment mentions it (that rule is absolute) — the commit
  message carries it.

## A reporting value this unit must add — decided 2026-10-14

Unit 327 left an open question and pinned the current answer with a test
(`verify_if_present_indeterminate_does_not_hold`): a **non-held**
indeterminate currently reports `no_attestation` on the metric and
`ProvenanceVerdictSummary::NoAttestation` on the job row, because the hold
label is scoped to `Indeterminate × Required`.

That is true today only because nothing produces the verdict. **This unit makes
it reachable**, and from then on a `VerifyIfPresent` scope with a
misprovisioned trust root or an unreachable upstream would report *"allowed
unsigned"* — which is the one reading an operator must not be given, because it
names the artifact's state instead of ours and sends them looking at the wrong
thing.

So this unit adds a non-held reporting value of its own for the indeterminate
outcome, in the same three places `HoldReason` already feeds (metric label,
`ProvenanceVerdictSummary`, `result_summary`), and updates
`docs/metrics-catalog.md`, which `ProvenanceVerifyResult`'s rustdoc declares a
normative coupling. The pinning test from 327 changes with it — that is the
intended route, which is why 327 wrote the test rather than leaving the
behaviour untested.

## Acceptance

- A test: fetch failure under `Required` ⇒ **no** `ProvenanceRejected`, **no**
  `ArtifactRejected`, status unchanged, and the job's `result_summary` names
  the new hold reason rather than `rejected:…`.
- A test: fetch failure under `VerifyIfPresent` ⇒ the artifact still releases
  on its normal window, byte-for-byte the behaviour before this item.
- A test: fetch failure under `Off` ⇒ unchanged.
- A test: a **non-held** indeterminate reports its own value, not
  `no_attestation` — and `docs/metrics-catalog.md` carries it.
- The orchestration no longer constructs `ProvenanceRejectReason::RekorNotFound`
  at all. After this item its only producers are in the keyless verifier, where
  the variant means what its rustdoc says — a readable proof that did not
  verify, or a bundle whose own log material is absent or unparseable. Pin that
  with a counter-assertion on the remaining sites, not a grep.
- The existing fetch-failure tests are rewritten with their new verdict stated
  in the report, not deleted.
- Full gate green. No issue/MR references in code comments.

## Out of scope

- Any retry/backoff change on the provenance-verify job. The fetch already has
  its own retry budget; this item changes what happens *after* it is exhausted.
- `Retry-After` on the resulting hold — #314's open question, untouched.
- Artifacts already `Rejected` from a past fetch failure. Naming and repairing
  that population is a maintainer decision recorded on #350, not work here.
