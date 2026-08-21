# 129 — The crates publish must survive a partial failure

Issue: #186 (first of two items; the second is `130-release-precondition-registry-version.md`).

## Why

The `v0.11.0-beta.7` publish uploaded `hort-domain 0.11.0-beta.7` successfully,
then broke on the next crate. Re-running the same tag — after the underlying
cause was fixed — failed immediately at crate one:

```
Publishing crates/hort-domain ...
    Updating `hort-crates` index
error: crate hort-domain@0.11.0-beta.7 already exists on `hort-crates` index
```

So one partial success makes the whole tag unrepeatable: the five crates that
never uploaded can never be uploaded at that version, and the release has to be
abandoned for a fresh pre-release. The cost grows the further down the chain
the first failure happens — a break at crate five burns the tag just as
completely as a break at crate two.

## What the observed failure establishes — build on this, do not re-derive

**The refusal is cargo's, client-side, and hort never sees the request.**
Cargo refreshes the index (`Updating \`hort-crates\` index`) and then declines
on its own, naming the index as the source of the fact. No upload is issued.

**Therefore a server-side fix is not available and must not be attempted.**
hort's ingest is already idempotent on identical content —
`IngestUseCase::ingest` (`crates/hort-app/src/use_cases/ingest_use_case.rs:825`)
documents "Duplicate check by path — idempotent on same hash, conflict on
different", and `:2444-2470` short-circuits on the declared hash before any
bytes are written. That path is simply unreachable here, because cargo stops
first. Do not change ingest; it is not the problem.

## What to do

Query the index for the exact `name@version` **before** invoking
`cargo publish`, and skip that crate when it is already present.

- **The check is an index lookup, not error-message matching.** Cargo's
  wording is not a stable contract, and by the time cargo prints it the exit
  status is already indistinguishable from a real failure. An index query
  tests exactly the condition cargo itself tests, before the attempt.
- **Never skip on exit status.** A "non-zero? keep going" loop would convert
  every genuine failure into a silent skip and ship a release with crates
  missing — strictly worse than today's loud break. This is the single most
  important constraint in the item.
- **Log every skip**, naming crate and version. A resumed publish that says
  nothing reads exactly like a fresh one.
- A version already in the index is immutable and content-addressed, so
  continuing past it is safe. That argument extends to **nothing else**.

## Deliberately not in scope

- **Server-side dedup.** See above — unreachable, and already correct.
- **The different-content case.** If a path exists with a *different* hash,
  hort raises `Conflict("path … already exists with different content")`. That
  is a genuine stop-and-think condition — the packaged bytes changed between
  attempts — and must stay fatal. Do not fold it into the skip.
- **Yank/replace semantics** (#178), and the quarantine-window question, which
  is settled separately (#187).

## Done when

- A publish re-run over a partially-published version skips the crates already
  in the index, completes the remaining ones, and exits 0 — logging each skip
  by name and version.
- Any other `cargo publish` failure still fails the job.
- The skip decision is verifiable without a live registry: a unit-testable
  helper or a documented dry-run path, not "we will see at the next release".
  The project already has index-querying helpers under `scripts/ci/`
  (`vetted-index-preflight.sh`, `locked-registry-deps.sh`) — prefer extending
  that established shape over inventing a new one.
