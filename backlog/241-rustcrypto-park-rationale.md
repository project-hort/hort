# 241 — The RustCrypto park in `renovate.json` has an expired reason and a dead pointer

**Issue:** #300 · **Branch:** `agent/300-rustcrypto-park-rationale`
**Governing decisions:** #249 (every park carries an unpark trigger) ·
`ba10fb3e` (cargo leaves Dependabot; GitLab Renovate is the single cargo entry
point).

## Why

The oldest `packageRules` entry in `renovate.json` reads:

> RustCrypto digest 0.10->0.11 migration is mid-flight; hold sha2/hmac/md-5/sha1
> until a coordinated bump. Mirrors the ignore in `.github/dependabot.yml`.

Both sentences are false today.

**The migration is not mid-flight; it is done.** The workspace stands at
`sha2 = "0.11"`, `md-5 = "0.11"`, `sha1 = "0.11"`, `hmac = "0.13"`
(`Cargo.toml:317-320`). The coordinated bump the rule waits for has happened. So
the rule now holds four crates on a line they left long ago, and what it
actually blocks is the *next* jump — for which no reason has ever been written.

The `sha2 0.10.9` still in `Cargo.lock` is **not** the counter-evidence: that is
the sigstore adapter's explicit, documented pin
(`crates/hort-adapters-provenance-sigstore/Cargo.toml`), because
`Verifier::verify_digest` takes a `sha2` hasher by value and that type must be
the same major sigstore compiled against. That pin is intended and unrelated to
this rule.

**The mirror no longer exists.** `ba10fb3e` removed the cargo ecosystem from
`.github/dependabot.yml` entirely, replacing it with a comment block explaining
that Renovate is the single cargo entry point. There is no cargo ignore left to
mirror.

This is the same failure #249 closed at four other sites, one step further
along: there the *carrier* was unreliable, here the *reason* has expired. A park
whose reason no longer holds is a silent freeze — it holds, and nobody knows
against what any more. It is also the only entry in the file with a reason but
**no unpark trigger**; after #249 the trigger is the convention, and this is the
remaining exception.

**Why #249 did not absorb it:** "the five existing rules stay byte-identical"
was that item's explicit acceptance criterion, and lifting a park is a decision,
not tidying. The run reported the find instead of doing it in passing.

## Measure before deciding

The decision turns on one fact that must be **measured, not assumed**: whether
the RustCrypto/`digest` line is actually uniform across the graph, or whether a
second line still stands.

    cargo tree -d -e normal | grep -A3 digest

Run it in the toolchain sandbox. Two lines in the graph would mean the coupling
is real and only the description is stale — which selects option 2 below.

## The decision — one of two, not both

1. **The rule goes.** The coordinated bump happened, so there is nothing left to
   hold. Future RustCrypto jumps arrive as ordinary Renovate MRs and are judged
   one at a time, which is what the other majors already get.
2. **The rule stays, re-argued.** If there is a reason to keep these four
   coupled — the next jump forcing the same coordination, or a second `digest`
   line in the graph — then *that* reason goes in, with its unpark trigger.

Either way the `.github/dependabot.yml` sentence goes.

## Acceptance

- The state of the RustCrypto line in the graph is **measured**, and the
  measurement is in the report.
- The entry is either removed or carries a reason **and** a trigger that are
  true today.
- The `.github/dependabot.yml` reference is gone.
- No version change; `Cargo.lock` untouched. If the measurement turns out to
  require one, that is its own unit — say so and stop.
- The other seven `packageRules` entries stay byte-identical.
- `renovate.json` still parses as JSON, and the file keeps its one-object-per-
  rule shape.

## Explicitly not in this item

- No RustCrypto version bump, in either direction.
- No change to the sigstore `sha2 0.10.9` pin or its comment.
- No revisiting of the four parks #249 added — they carry current reasons and
  triggers.
