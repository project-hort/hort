# 119 — Derive the quarantine anchor from content-level age evidence

Issue: #163. **Authority: [ADR 0054](../docs/adr/0054-content-level-age-evidence-anchors-quarantine.md)**.
Second of two units; **depends on backlog 118** (the projection must exist
and be written before anything derives from it). Do not start this before
118 has merged.

## What

Replace per-row anchor derivation with ADR 0054's rule: the anchor is the
**minimum of the applicable age sources**, with the existing future-skew
clamp retained.

1. **Primary source** — `first_seen_at` for this content hash (backlog
   118). Always applicable; no opt-in.
2. **Second source** — the upstream publish time observed through **this
   repository's own** mapping, and only where that mapping has
   `trust_upstream_publish_time` enabled. It may move the anchor
   **earlier**, never later. A value observed through another
   repository's mapping MUST NOT influence this repository's anchor: the
   opt-in is a per-mapping trust statement and does not transit
   repositories. This is the ADR's load-bearing scoping rule — pin it
   with a test that would fail if a cross-repository value leaked in.
3. **Both paths** — `ingest_inner` and `register_by_hash_inner` derive the
   anchor identically. The leader/follower asymmetry must disappear as a
   consequence of the shared derivation, not as a special case; pin that
   with a test asserting the same anchor for the same content whichever
   path minted the row.
4. **Interaction with the descendant carve-out** (already caller-independent):
   determine and document which wins when both apply — they are both
   "shorten the window" rules, so the honest answer is almost certainly
   `min`, but state it explicitly in code and test it rather than letting
   it fall out of the code order.
5. **Clamp** — keep `min(candidate, now)`. An ancient value is NOT
   clamped, per ADR 0054's rationale (elapsed ecosystem exposure is
   exactly what the window proxies); a future-dated one is nonsense and
   is clamped as today.
6. **Seed-import** keeps absolute precedence: an explicit
   `quarantine_anchor_override` is never overridden by any derived value.

## Docs

Update the `trust_upstream_publish_time` operator documentation to state
its new role as the optional second source, and flip ADR 0054's status
from **Proposed** to **Accepted** in the same MR — the decision is
realised when this lands. ADR 0016's matrix entry already exists; verify
it still reads true against what you implemented and correct it if not.

## Constraints

- Comment provenance rule: invariants only.
- 100 %-coverage crates: every branch of the derivation, including "no
  trusted mapping", "trusted mapping but no publish time", "both sources
  present", and the descendant-carve-out interaction.
- Release **authority** is untouched: `Artifact::release` still requires
  this artifact's own `ScanSucceeded` / `ScanWaived` (ADR 0007). Any
  change that lets the timer influence authority is a hard block.

## Acceptance

- The same content registered into two repositories yields the same
  anchor, whichever path minted each row.
- A repository whose mapping has the opt-in disabled anchors on
  `first_seen_at` alone, even when a sibling repository observed an
  earlier upstream publish time.
- Seed-import anchors are preserved verbatim.
- `cargo test --workspace` green; fmt/clippy/audit/deny clean; the E2E
  quarantine scenarios still pass (operator-side full compose suite —
  this item touches quarantine timing, so it is E2E-gated).
