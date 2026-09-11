# 178 — one canonical version ordering, and a guard that VD implies it

**Issue:** #233 · **Branch:** `agent/233-maven-version-discovery` ·
**Blocking: the branch must not reach `develop` without this.**

## Problem

Item 172 made `MavenFormatHandler` declare the `VersionDiscovery`
capability group. Item 171's apply-time rejection keys on exactly that, so
from that commit onward **`prefetchPolicy.triggers: [scheduled]` on a Maven
proxy is accepted at gitops apply**. At run time it does nothing:

- `crates/hort-app/src/task_handlers/prefetch_tick.rs` — the
  `version_discovery()` pre-flight now passes for Maven.
- The next gate, `let Some(ordering) = ordering_for_format(&repo.format)
  else { continue }`, silently `continue`s. Not even a log line.

That is "policy field accepted at apply, inert at runtime" — the ADR 0015
hard block, and precisely the thing item 171 exists to prevent. The
accepting commit is on this branch, so the closing commit belongs on it too.

The capability declaration is **truthful**, and that matters for choosing
the fix: Maven implements the whole group (including
`extract_upstream_versions` over the A-level `maven-metadata.xml`), and
`MavenVersionOrdering` already exists in
`hort-app::use_cases::index_serve_filter` and is wired into the Maven serve
path today. Nothing is missing but the wiring on the consumer side.

## Why this is not just "add the Maven arm"

Adding one arm would close this instance and leave the mechanism that
produced it. The mechanism is that the *same* fact — which formats have a
version ordering — is written down three times:

1. `prefetch_tick::ordering_for_format` (private match, `_ => None`),
2. a second private match in
   `use_cases/self_service_prefetch_use_case.rs` (`_ => None`),
3. implicitly, by which handlers return `Some` from `version_discovery()`.

Two duplicated matches must be kept in agreement with each other and with
the handlers, by hand. `prefetch_tick`'s own comment describes the
invariant it relies on — "npm/cargo/pypi are exactly both the
VersionDiscovery participants and the only Phase-1-ordering formats, so
that check already guarantees this resolves" — and item 172 is what breaks
it. `self_service_prefetch_use_case` carries a matching comment naming a
four-site coupling that "MUST move together". A rule enforced by a comment
saying four places must move together is the smell; make it one place.

Making the match exhaustive over `RepositoryFormat` is **not** the answer
either — there are 34+ variants, nearly all of which genuinely have no
ordering, so exhaustiveness buys a wall of `=> None` and two more edits per
future format.

## What to change

**One canonical mapping.** Add a `pub fn ordering_for_format` to
`hort-app::use_cases::index_serve_filter`, beside the ordering impls it
returns, and have both call sites use it. Delete both private matches. Add
the Maven arm there, once.

Return `Option<&'static (dyn VersionOrdering + Send + Sync)>`. The
orderings are zero-sized unit structs, so `Send + Sync` is free — and it
should let `prefetch_tick` drop the scoped-block dance its comment
describes (holding a `!Send` `&dyn VersionOrdering` across an `.await`
would taint the enclosing boxed future). Verify that simplification rather
than assuming it; if the block is still needed for another reason, keep it
and say why.

**A guard that the two capabilities cannot diverge.**
`crates/hort-formats/tests/version_discovery_participation.rs` already
classifies every `RepositoryFormat` variant with a wildcard-free exhaustive
match and cross-checks it against the real handlers. Extend it with the
parity assertion: for every variant, `version_discovery().is_some()` iff
`ordering_for_format(..).is_some()`. That is the structural close — the
next format that declares the group without an ordering fails a
sub-second, DB-free test instead of silently skipping a policy in
production.

**Make the residual runtime branch loud.** With the guard in place the
`None` branch is unreachable for a participating format, so reaching it is
a programming error, not a normal skip. Replace the bare `continue` with an
error-level `tracing` event carrying repository and format, plus a counter,
then continue. Silence is what hid this.

**Enable the upstream half.** `crates/hort-formats-upstream/src/lib.rs`
rejects Maven `list_versions` with `UpstreamFetchError::UnsupportedFormat`.
Enable it, so the self-service prefetch endpoint resolves Maven versions
through the same path. This *is* a deliberate behaviour change for Maven
repositories on that endpoint — it is the fourth site of the coupling and
it is authorised here explicitly; it fetches the same `maven-metadata.xml`
the scheduled tick already fetches, under the same policy gate.

## Read first

- `crates/hort-app/src/task_handlers/prefetch_tick.rs` — the pre-flight,
  the ordering gate and its comment, `ordering_for_format`, and the two
  tests `ordering_for_format_supports_npm_cargo_pypi` /
  `ordering_for_format_does_not_support_maven_oci_helm` (the second one
  asserts today's wrong answer and must change).
- `crates/hort-app/src/use_cases/self_service_prefetch_use_case.rs` — the
  second match and the four-site coupling comment, which this item
  discharges and which must be rewritten rather than left claiming a
  coupling that no longer exists.
- `crates/hort-app/src/use_cases/index_serve_filter.rs` — `VersionOrdering`
  and the four impls, including `MavenVersionOrdering`.
- `crates/hort-formats/tests/version_discovery_participation.rs`.
- `crates/hort-formats-upstream/src/lib.rs` — the `list_versions` dispatch.

## Acceptance

- Exactly one `ordering_for_format` exists in the workspace; both former
  call sites delegate to it and neither retains a private match.
- `scheduled` on a Maven proxy plans versions at run time — a test drives
  `PrefetchTickHandler` over a Maven repository with a stub upstream
  serving `maven-metadata.xml` and asserts the planner selects versions in
  `MavenVersionOrdering` order (not lexicographic: `1.10.0` above `1.9.0`).
- The participation guard asserts the VD-iff-ordering parity across every
  `RepositoryFormat` variant, and fails if either side is changed alone.
- The unreachable ordering-`None` branch emits an error event and a
  counter; a test asserts the counter, so the branch is not merely
  annotated but observed.
- `hort-formats-upstream` resolves Maven `list_versions` instead of
  returning `UnsupportedFormat`, with a test.
- Full local gate green per the pre-push checklist, `DATABASE_URL` set.

## Governing decisions

ADR 0015 (a policy field accepted at apply and inert at runtime is a hard
block; the structural close is fail-closed rejection, never a degraded
runtime fallback), ADR 0005 (capability groups), ADR 0053 D5.
