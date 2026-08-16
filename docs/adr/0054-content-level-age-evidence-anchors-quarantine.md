# 0054 — Content-level age evidence anchors the quarantine window

- **Status:** Proposed
- **Enforced by:** not yet mechanised — this ADR records the decision; the
  `first_seen_at` projection, the anchor derivation, and the second-source rule
  are implemented under the issue this ADR governs. Until that lands, the
  implemented behaviour is the one this ADR replaces (per-row anchoring at
  ingest time, optional upstream publish time under
  `RepositoryUpstreamMapping.trust_upstream_publish_time`).
- **Supersedes:** —
- **Relates:** [0007](0007-fail-closed-quarantine-release-predicate.md) (the
  quarantine window and the fail-closed release predicate this anchors),
  [0016](0016-cross-opt-in-interaction-matrix.md) (the cross-opt-in matrix the
  second-source rule must be entered in),
  [0026](0026-streaming-metadata-projection.md) (projection discipline).
  Source decision: issue #163, maintainer's 2026-08-16 Matrix decision.

## Context

The quarantine window is not a scan queue. It is a **proxy for elapsed
ecosystem exposure**: the assumption that if content has been available in the
world for the window's duration, the ecosystem's scanners, advisories, and
researchers have had the opportunity to discover what is wrong with it. hort's
own scan verdict is a separate, independent gate — ADR 0007's release predicate
requires this artifact's own `ScanSucceeded` / `ScanWaived` regardless of the
timer.

Two facts about the current implementation motivated this decision.

**The anchor is per-repository-row, and the row is minted by whichever code
path happens to create it.** One CAS entry can carry several `artifacts` rows —
one per repository — and the anchor lives on the row. A cross-repository
pull-through coalesce therefore produces different anchors for the same content
in the same repository depending on which caller won the dedup race: the
fetching leader records the parsed upstream publish time, a follower minting its
row over already-resident CAS content records `now` (issue #163). Two
identically configured deployments can diverge with nothing in the configuration
differing.

**The one alternative to "now" was an upstream assertion.**
`RepositoryUpstreamMapping.trust_upstream_publish_time` anchors the deadline to
an upstream-asserted `published_at`. It is a per-mapping opt-in precisely
because that input is attacker-influenceable: the existing clamp is a
**future-skew clamp only** (`min(upstream_ts, now)`), so a claimed *ancient*
publish time is bounded nowhere and collapses the window immediately. Freshly
uploaded malware carrying forged old metadata is exactly the case the opt-in
exists to bound — it leaves only hort's own scanner at day zero, when scanners
are weakest.

The maintainer's observation resolves both: **hort already possesses an age
fact it generates itself.** The time hort first ingested that content, in any
of its own repositories, is an observation — not an assertion by a third party.

## Decision

**Anchor the quarantine window on the earliest defensible evidence of the
content's age, and hold that evidence at the content level, not on the
per-repository row.**

1. **`first_seen_at` (primary, always available).** Per content hash, the
   minimum over hort's own ingest observations across all repositories of this
   instance. No opt-in: it requires trusting nobody.
2. **Trusted upstream publish time (optional second source).** Where a
   repository's own mapping has `trust_upstream_publish_time` enabled, that
   mapping's observed publish time may move the anchor **earlier** — never
   later. A value contributed through another repository's mapping may be
   displayed and audited but MUST NOT shorten this repository's window; the
   opt-in is a per-mapping trust statement and does not transit repositories.
3. **Anchor = the minimum of the applicable sources**, with the existing
   future-skew clamp retained.

### Why an unforgeable observation is the right primary source

An upstream claim can be backdated. An observation cannot. The most an attacker
achieves by influencing `first_seen_at` is making hort see the bytes *earlier* —
which requires the content to genuinely have existed that much earlier, during
which the ecosystem had precisely the same exposure the window is a proxy for.
The attack that motivates the `trust_upstream_publish_time` opt-in therefore has
no analogue here.

`first_seen_at` is also structurally conservative: hort cannot observe content
before it is published, so first-seen is always a **late** estimate of real
publication, and anchoring on it can only ever hold content *longer* than the
truth would justify.

### Why the zero window that follows is correct, not a concession

Content that hort first saw long ago and is now registering into a second
repository has already had its ecosystem exposure. Holding it another full
window adds no observation the world has not already had. Release still requires
this artifact's own clean scan verdict (ADR 0007) — the anchor governs the
timer, never the authority. A zero-length window is therefore the intended
outcome of the model, not a weakening of it.

### Consequences

- **The leader/follower asymmetry dissolves.** A coalesced follower needs no
  publish-time hint threaded to it: it derives the same content-level anchor the
  leader derives. Issue #163's defect disappears as a property of the model
  rather than being patched at each call site.
- **`min` is order-insensitive**, so the anchor is race-independent by
  construction: observation order cannot change the result.
- **`first_seen_at` must survive per-row deletion.** Retention and GC remove
  per-repository rows; the content-level fact must not be derived from live rows
  or an artifact would lose its age to routine cleanup. It is a projection over
  ingest observations, in the ADR 0026 sense.
- **ADR 0016 matrix entry required.** The two-source rule is a new
  operator-influenced input to the release-gate computation and must be
  registered in the cross-opt-in interaction matrix, including its interaction
  with `scan_backends: []` — the existing
  `trust_upstream_publish_time_requires_scan_backends` apply-time rejection
  continues to apply unchanged to the second source.
- **The first-seen source needs no such rejection rule**, because it introduces
  no attacker-asserted input; this asymmetry between the two sources is the
  point of separating them.

## Alternatives considered

- **Thread the upstream publish hint through the follower call sites.** Patches
  one leg of one race, leaves the anchor a per-row fact, and keeps the
  attacker-assertable source as the only alternative to `now`. Rejected.
- **Document the leg-scoped behaviour and pin it with a test.** Makes the
  non-determinism predictable without removing it. Rejected once an unforgeable
  source was available.
- **Unfiltered minimum over all repositories' upstream claims.** Would let a
  repository proxying an untrusted mirror shorten the window of a repository
  proxying the genuine upstream — the ADR 0016 cross-opt-in collapse pattern, in
  the weakening direction. Rejected; it is the reason for the per-mapping
  scoping in decision point 2.
