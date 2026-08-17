# 0054 — Content-level age evidence anchors the quarantine window

- **Status:** Accepted
- **Enforced by:** `hort_domain::policy::quarantine_anchor::derive_quarantine_anchor`
  — the pure minimum over the applicable age sources, called by BOTH minting
  paths (`IngestUseCase::ingest_inner` and
  `IngestUseCase::register_by_hash_inner`), which is what makes the
  leader/follower asymmetry a property of the model rather than a per-call-site
  patch. The age evidence is read live through
  `ArtifactRepository::first_seen_for_checksum` (`MIN(created_at)` over the
  artifact rows sharing the hash, on the pre-existing `idx_artifacts_checksum`);
  there is no projection table and no migration. The second-source scoping rule
  is structural: `derive_quarantine_anchor` takes no repository identity and
  holds no mapping table, so a trusted upstream value can only enter through the
  caller that owns this repository's own mapping. Its cross-opt-in entry is in
  [0016](0016-cross-opt-in-interaction-matrix.md).
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
- **`first_seen_at` is derived, not stored** (amended 2026-08-16 — see the
  amendment below). It is `MIN(created_at)` over the artifact rows that share the
  content hash, served by the existing `idx_artifacts_checksum`. The accepted
  cost is that the evidence does not outlive the rows: once retention purges the
  last row for a hash, a later re-ingest of the same bytes anchors at that
  ingest. That direction is conservative — a lost observation can only lengthen a
  window, never shorten one.
- **ADR 0016 matrix entry required.** The two-source rule is a new
  operator-influenced input to the release-gate computation and must be
  registered in the cross-opt-in interaction matrix, including its interaction
  with `scan_backends: []` — the existing
  `trust_upstream_publish_time_requires_scan_backends` apply-time rejection
  continues to apply unchanged to the second source.
- **The first-seen source needs no such rejection rule**, because it introduces
  no attacker-asserted input; this asymmetry between the two sources is the
  point of separating them.

## Amendment (2026-08-16) — derive the evidence, do not materialise it

The decision above is unchanged in substance: the anchor is still the earliest
defensible evidence of the content's age, still the minimum of the applicable
sources, and the primary source is still hort's own unforgeable observation.
Only the **mechanism** changed.

The first implementation materialised the fact in a dedicated content-level
table so it would outlive the per-repository rows. Reviewing what that bought,
the answer was exactly one property — survival of retention/purge — because
everything else is available from a live `MIN(created_at)` over the artifact
rows sharing the hash, on an index that already exists. The materialised form
additionally required a write path on both minting paths, a `LEAST` upsert whose
whole purpose was to make concurrent observers converge (a live aggregate has no
such race), a one-time seed to recover existing history, and a permanently
growing table.

The maintainer's decision (2026-08-16): the purge-then-re-ingest case does not
justify a standing table and further migrations. Derive it.

**What is given up, stated plainly.** Content that hort purged and later fetches
again loses its original age evidence and re-anchors at the new ingest. The
window it then serves is longer than the truth would require, never shorter, so
the failure direction is safe; and no attacker gains anything, since the
alternative sources are unchanged. If that case ever becomes load-bearing, the
materialised form is the known answer and this amendment is the record of why it
was not taken now.

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
