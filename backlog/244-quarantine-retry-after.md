# 244 — The response that triggers a quarantine reports a flat 3600 s `Retry-After`

**Issue:** #240 · **Branch:** `agent/240-quarantine-retry-after`
**Governing decisions:** ADR 0007 (quarantine + release authority — untouched;
this is the advertised timer, not the gate) · ADR 0054 (anchor derivation — the
deadline is `anchor + window`, and the anchor may legitimately predate this
ingest).

## Why

A pull-through GET that ingests an artifact and quarantines it answers
`503 UNAVAILABLE` with a flat `retry_after_seconds: 3600`, whatever the policy's
actual window. A *later* read of the same row returns a correctly computed
remaining time. Observed twice in one UAT round, on two repositories, against a
48-hour policy — `3600` on the triggering response, `143914` on a later one.

The cause is not a bug in the computation. `crates/hort-http-oci/src/
quarantine.rs::check_quarantine` reads `artifact.quarantine_deadline`, a
**transient, non-persisted** field: the schema stores only the immutable anchor
`quarantine_window_start`, and the deadline is
`effective_quarantine_deadline(anchor, duration)` computed live at the use-case
layer (`crates/hort-adapters-postgres/src/mappers.rs` maps it to `None`
unconditionally). On the ingest path the artifact was quarantined moments
earlier in the same request and the value the handler holds was never hydrated,
so the `3600` fallback fires.

**The defect is that the one response where the deadline is most certainly
known — hort has just computed the window in order to create it — is the one
response that cannot see it.**

It is a correctness and load problem, not a security one. The window is
unaffected and the client learns nothing it should not. But the wrong value
lands on the response a client is most likely to act on, and it is wrong in the
direction that generates load: a client honouring `Retry-After` returns after an
hour on a 48-hour window and is refused again, roughly 47 times, each retry
costing a repository resolution and a row read.

## The trap

**Do not compute `now + duration`.** ADR 0054's anchor may legitimately predate
this ingest — in the observed case `library/hello-world` inherited an
eight-hour-old anchor through the `first_seen` source, which is exactly why the
correct later value was `143914` and not `172800`. A fix that reports the policy
duration is wrong in the other direction, and it is wrong invisibly, because it
looks right on a freshly-seen artifact.

## Direction

Hydrate `quarantine_deadline` on the artifact the ingest path hands back, so the
handler's existing computation is simply correct. `ArtifactUseCase::
hydrate_quarantine_deadline` already exists and is what the later read goes
through — reuse that path rather than writing a second one.

**Prefer this over special-casing the fallback in the OCI handler.** The field's
contract is that the use-case layer hydrates it; the ingest path just is not
honouring it. Patching the handler leaves every other format's quarantine
response with the same staleness, waiting to be rediscovered.

The `3600` fallback stays for the genuinely-unknown case — but say whether that
case is still reachable once ingest hydrates, either way.

## Two adjacent facts, for a verdict rather than a fix

Both live in the same expression the fix touches, and both were measured during
the base-image warm work. Neither is in scope; state a verdict on each so the
next reader does not rediscover them.

1. **Past the deadline the clamp is useless.** `(deadline - now).max(1)` yields
   `Retry-After: 1`, so a well-behaved client returns every second and learns
   nothing until the release sweep ticks — measured at five to ten minutes
   beyond the deadline, because release follows the sweep tick and not the
   individual artifact.
2. **A `provenance_hold_indefinite` artifact gets no `Retry-After` at all** —
   deliberately, since that hold has no self-resolving deadline. Worth stating
   because it means "no header" and "header says 1" are two different states a
   client cannot distinguish from the status code alone.

## Read first

- `crates/hort-http-oci/src/quarantine.rs` — `check_quarantine`,
  `DEFAULT_QUARANTINE_RETRY_AFTER_SECS`, and the doc comment naming the
  hydration contract.
- `crates/hort-app/src/use_cases/artifact_use_case.rs` —
  `hydrate_quarantine_deadline` and its zero-policy-port-call fast path.
- `crates/hort-app/src/use_cases/ingest_use_case.rs` —
  `decide_and_apply_quarantine` (the decision that knows the window) and the
  artifact the pull-through path returns.
- `crates/hort-domain/src/policy/scan.rs` — `effective_quarantine_deadline`.

## Acceptance

- The response that triggers the quarantine carries the same
  `retry_after_seconds` a later read of the same artifact would carry, computed
  from the **derived anchor**, not from `now` and not from the policy duration.
- A test pinning the inherited-anchor case: an artifact whose anchor predates
  this ingest reports the remaining time from that anchor, not the full window.
- The fix is in the use-case layer, so a second format's quarantine response
  inherits it without its own change.
- A verdict on whether the `3600` fallback is still reachable.
- A stated verdict on each of the two adjacent facts above.
- No change to the window, to the release predicate, or to `check_quarantine`'s
  suppression of the header for an indefinite hold.
- Gate green.

## Explicitly not in this item

- No change to any quarantine duration or to ADR 0054's anchor derivation.
- No change to the clamp or to the indefinite-hold suppression — verdicts only.
- No persistence of the deadline. It is derived on purpose, so a later
  `quarantineDuration` edit takes effect without a backfill.
