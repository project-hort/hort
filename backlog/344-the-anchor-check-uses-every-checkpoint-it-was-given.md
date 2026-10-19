# 344 — The anchor check uses every checkpoint it was given

**Issue:** #352 · **Branch:** `agent/352-integrity-verifier-verdict`
**Governing decisions:** ADR 0057 (event-chain verification is default-on; the
`{ok, broken, missing_checkpoint}` catalogue and its exit codes) · ADR 0002
(tamper-evident per-stream chain).

**Confirmed by the maintainer 2026-10-18** (#352 moved to `ready`). Three
findings, one function, one correction — they are a single unit because each
one alone leaves the other two able to hide a head mismatch.

## What is true today

All three live in `verify_against_checkpoint`
(`crates/hort-domain/src/events/chain.rs:605-677`).

**(a) A coverage gap returns before the violation can be computed.** The
sequence-gap check (`:617-627`) and the staleness check (`:629-639`) each
`return AnchorVerdict::MissingCheckpoint(…)`. The head comparison is
`:641-651`, after them. So when the anchor set is stale or has a hole, the
head mismatch is never calculated — although `live_heads` and
`newest.stream_heads` are both already in hand.

`roll_up` (`:699-702`) states the opposite:

> *"`Broken` dominates `MissingCheckpoint` dominates `Ok` — a real violation
> is never masked by a coverage gap."*

The dominance is real but it can only rank verdicts that exist. The promise is
not weakened here, it is inverted: the one case it names is the one case that
cannot reach it.

**(b) A duplicate `checkpoint_seq` is silently collapsed.** `:617-620` does
`seqs.sort_unstable(); seqs.dedup();`, so two checkpoints carrying the same
`checkpoint_seq` count once and the contiguity test passes. `:613`
(`max_by_key`) picks one of them with no tiebreak. The other is validly
signed, may attest a different head, and is never looked at again.

**(c) Only the newest checkpoint's heads are ever compared.** `:641-651`
consults `newest.stream_heads` and nothing else. The older checkpoints are not
unused — their *presence* carries contiguity (`:617-627`) and the
`SealUnanchored` search does scan all of them (`:667-676`) — but **their
statement about head hashes is never read.** `CheckpointAnchorPort`
(`crates/hort-domain/src/ports/checkpoint_anchor.rs:47-49`) says so plainly:
the core *"selects the newest by `checkpoint_seq` and checks the sequence is
gap-free"*.

The consequence of (c) is the attack (a) and (b) also enable: rewrite a stream
wholesale, wait for the next scheduled checkpoint, and the run is judged
against that one. The older checkpoint that contradicts it was fetched,
signature-checked, and set aside.

## What to build

One corrected verdict function. The three parts are not independent fixes:

- **Compute the head comparison before returning a coverage verdict.** The gap
  and staleness findings must still be reported — they are real — but the
  function must determine whether a `Broken` also exists and let `roll_up` do
  what its comment says. Do not reorder the checks into a different silent
  priority; produce both facts and rank them where the ranking already lives.
- **A duplicate `checkpoint_seq` is a violation, not a duplicate.** Two
  signed checkpoints claiming the same sequence number is a thing that cannot
  legitimately happen; `dedup()` turns it into a thing that did not happen.
  It needs its own verdict, not a silent collapse, and `max_by_key`'s
  tiebreak must stop being arbitrary.
- **Every checkpoint's head statement is evidence.** A stream head that
  contradicts *any* signature-verified checkpoint is a mismatch, whether or
  not that checkpoint is the newest. A head legitimately moves forward between
  checkpoints, so the comparison against an older anchor is not "equal" — the
  implementer determines the correct relation (the chain is append-only, so a
  prior anchored head must be reachable from the current one) and states the
  reasoning in the commit body. If establishing reachability needs a read the
  pure core does not have, say so in the report rather than weakening the
  check to fit: that is a port question, not a reason to keep comparing only
  the newest.

`verify_against_checkpoint` is pure and must stay pure — no I/O, no panic on
caller input (the `chrono::Duration::MAX` guard at `:630-636` is the existing
shape).

## Acceptance

1. A stale or gapped anchor set **plus** a head mismatch yields `Broken`, not
   `MissingCheckpoint`. One test per coverage reason.
2. A coverage gap with no head mismatch still yields `MissingCheckpoint` with
   the same reason as today. No reclassification of the honest cases.
3. Two checkpoints sharing a `checkpoint_seq` are reported, not deduplicated —
   including when they agree with each other.
4. A live head that contradicts a non-newest signature-verified checkpoint is
   reported, with a test that anchors the *older* checkpoint to the
   contradicting head and leaves the newest consistent.
5. A head that legitimately advanced between two checkpoints is **not**
   reported. This is the false-positive guard and it is as load-bearing as 4.
6. `verify_against_checkpoint` remains free of I/O and does not panic on any
   caller input, including an absurd cadence.
