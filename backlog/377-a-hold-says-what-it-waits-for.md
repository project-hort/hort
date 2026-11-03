# 377 — A hold says what it waits for

**Issue:** #400, entry **E43** · **Branch:** `agent/400-operator-messages` ·
item 3 of 3.

**Maintainer decision (Matrix, 2026-11-03):** build it as recommended — the
hold becomes a verdict like its two siblings. This item was parked before that
because both available outcomes looked like they changed a stated intent; one
of them does not (see "What is not in the way" below).

## The gap, at its sharpest

A publisher whose push is held cannot learn **which of three different actions
is theirs to take** — and the system has already computed the answer.

`HoldReason` (`crates/hort-app/src/use_cases/provenance_orchestration.rs`)
distinguishes three cases on every verify, and its own docstring states that
distinguishing them is the point:

| hold reason | what the publisher must do |
|---|---|
| `PendingSignature` | this artifact may still be signed — **sign it** |
| `PendingSubject` | it can never be signed on its own — **push/sign the parent** |
| `Indeterminate` | nothing: *"we could not check"*, and the action is on **our** side (trust root, verifier, or the fetch retries) |

That three-way answer reaches three surfaces — a log line, a metric label and
the job row's `result_summary` — all of them operator-facing, and the type
keeps them together *"so the three cannot drift apart"*. **None of them is
reachable by the publisher**, and the job row is pruned by retention besides.

So the publisher sees `quarantined` with no provenance axis, identically in all
three cases, including the one where they did everything right and the work is
ours. That is the half of #350's disposition that was never paid: the hold is
safe and correctable, and its reason reaches nobody who can act on it.

## What is not in the way

**The opacity decision is about a different surface and a different
principal.** `crates/hort-http-core/src/artifact_gate.rs:192-196` says the
`503` body stays *"opaque to the **client**"* — that is the **anonymous
download path**, a puller fetching bytes. The verdict surface
`GET /api/v1/events?category=artifact` requires an **authenticated** caller and
filters artifact events **per event**
(`crates/hort-http-events/src/lib.rs:24-33`). A publisher reading their own
push is not the anonymous puller that decision was made about, and this item
does not touch the content route's body at all.

**The release gate is unaffected.** `read_path_provenance_clearance` looks for
exactly one thing — a `ProvenanceVerified` on the stream
(`crates/hort-app/src/use_cases/release_clearance.rs:127`), fail-closed
otherwise. A new event type is additive to it.

**What the decision does change** is one sentence, and it is a rustdoc rather
than an ADR (`crates/hort-domain/src/ports/provenance.rs:286-287`): *"no event
payload references it today (a hold emits no event at all — that absence **is**
the hold)."* Rewrite it to say what is now true and why, so the next reader
meets the decision rather than the contradiction.

## The outcome

**The third provenance outcome becomes an event, like its two siblings.**
`ProvenanceVerified` and `ProvenanceRejected` are events; the hold is the only
outcome that writes nothing, and that asymmetry is the defect.

Its payload is **which of the three the hold is waiting for** — the
`HoldReason` distinction, not the `IndeterminateReason` detail. That is
deliberate and the existing docstring argues it: the specific indeterminate
reason *"rides the verdict's own audit trail rather than splitting a reporting
label three ways"*, and the publisher's action is identical for all of them.
`HoldReason` is private to the app layer today, so the payload type belongs in
`hort-domain` beside the provenance port, with the app-layer enum mapping onto
it rather than a second copy of the three cases.

### The constraint that has to be designed in, not discovered

**Once per reason change, never once per attempt.** `STREAM_EVENT_CAP` is
**200** (`crates/hort-app/src/use_cases/mod.rs:300`), and a capped read cannot
tell a complete stream from a truncated one — which is exactly the hazard
`capped_stream_reads` exists for, and the release authority reads these streams.
The expiry backstop re-verifies at **every** window expiry and the
signature-arrival hook fires on every referrer, so an attempt log would walk an
artifact's stream toward the cap and make the authority derivation unreliable.
A hold that emits on a *transition* — first hold, or a change of which of the
three it waits for — is bounded by a tiny finite set.

So the emit site needs to know the artifact's current hold reason before it
appends. Establish how it does that, and whether the answer is on the stream
already or has to be read with the evidence (the paired read, as in #404) —
and say which in the report.

## Acceptance

1. **The publisher's three cases are distinguishable on the events surface.**
   One test per `HoldReason`, asserting the event is on the artifact's own
   stream and carries that case — not that "an event exists".
2. **Re-verifying an unchanged hold appends nothing.** A second verify at the
   same reason is a no-op on the stream; a verify whose reason *changed*
   appends once. This is the test that keeps the unit from becoming a stream
   flood, so it asserts a count, not a presence.
3. The release gate is unchanged: a held artifact with the new event still
   reads `Pending`, and a `ProvenanceVerified` still clears it. Assert both, so
   "additive" is proved rather than assumed.
4. The new event is wired everywhere a sibling is. **Derive that footprint from
   `ProvenanceRejected` rather than guessing it** — it is named in 19 files,
   including `domain_event.rs` (the variant, `event_type()`, and the two
   grouping matches), `entities/subscription.rs` (`EventTypeKind` plus the
   per-event projection), `events/chain/chain_vectors.rs`, the subscriptions
   DTO and the Postgres subscription repo. A `validate()` that rejects a
   malformed payload is part of it (the round-tripping doubles call it).
5. The rustdoc at `ports/provenance.rs:286-287` states what is true after this
   change, with the reason the absence is no longer the hold.
6. Every DB-backed test carries `#[serial(hort_pg_db)]`.
7. `CHANGELOG.md`: one entry — a held artifact now records why it is held, so a
   publisher can tell "sign it", "sign the parent" and "nothing for you to do"
   apart. Name that subscribers to the provenance event types will begin
   receiving it.

## Not in this item

- The content route's `503` body, which stays as decided.
- The `IndeterminateReason` detail as a publisher-facing field.
- The four entries of items 1 and 2.
