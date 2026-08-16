# 116 — Zero-window carve-out parity for the registration path

Issue: #161 (second defect, same family as backlog 115). One reviewable
unit. **E2E-gated: no MR until the operator's full compose suite is green
on this branch.**

## Evidence

With backlog 115 merged, `quarantine/proxy-multiarch-zero-window` still
fails on the release gate — but only two asserts remain (the edge asserts
now pass):

```
FAIL: child quarantine_window_start == created_at - 24h :: got 'f'
FAIL: child satisfies the release-sweep selection predicate
```

The gate's new FAIL-log dump proves the leg conclusively:

```
"register_existing_cas_blob: follower registering own per-repo row for
 coalesced cross-repo CAS hash", hash=b58899…  (the child manifest)
"register_by_hash: quarantine/scan/provenance gate resolved",
 quarantined=true, quarantine_anchor_override: None
```

## The defect

The referenced-tree-descendant zero-window carve-out lives ONLY in
`ingest_inner` (`crates/hort-app/src/use_cases/ingest_use_case.rs`
~2905–2945): it calls `content_references.find_by_target(repo, hash)` and
`is_referenced_tree_descendant(&refs)`, and back-dates the quarantine
anchor by the effective duration when true.

`register_by_hash_inner` (~4180–4280) deliberately does NOT — its own
comment says so: *"Unlike `ingest_inner`, no referenced-tree-descendant
zero-window carve-out … applies here … that carve-out stays scoped to
`ingest_inner` (out of scope for this item)."* That scoping was written
when this path served only seed-import and cross-repo mount. The
coalesced-follower leg now routes ordinary pull-through traffic through
it, so **the same artifact in the same repository gets a different
quarantine window depending on which caller won the dedup race** — the
leader gets the carve-out, the follower does not.

Production consequence: a follower-minted descendant sits a full window in
hold instead of inheriting its parent tree's. Fail-safe in direction, but
it violates the documented contract and makes quarantine timing
race-dependent.

## Change

In `register_by_hash_inner`, when `effective_duration_secs > 0` **and**
`quarantine_anchor_override.is_none()`, evaluate the descendant predicate
exactly as `ingest_inner` does — same `find_by_target` lookup, same
shared `is_referenced_tree_descendant`, same fail-safe on lookup error
(a lookup failure degrades to "not a descendant" = the full window, never
the zero window) — and back-date the anchor by `effective_duration_secs`
when it holds.

- `quarantine_anchor_override` (seed-import) keeps absolute precedence:
  an explicit anchor is never overridden by the carve-out.
- The predicate is topology-based (is this content already a
  `content_references` target of another already-ingested artifact in
  THIS repo), so it is caller-independent by construction; that is
  precisely why the leader/follower asymmetry is a defect and not a
  design choice. Mount callers gain the same parity, deliberately.
- Factor the shared logic rather than copying it if that is clean at this
  layer; do not change `ingest_inner`'s behaviour.
- Out of scope: the `trust_upstream_publish_time` clamp, which the same
  comment also scopes out — note it in the report, do not touch it.

## Tests

- `register_by_hash` with an existing `oci_index_member` edge targeting
  the hash → anchor back-dated by the effective duration (fails pre-fix).
- Seed-import caller with an anchor override + a descendant edge → the
  override wins, unchanged.
- Lookup error → full window (fail-safe pin).
- Non-descendant → full window, unchanged.
- The existing `register_by_hash_non_seed_quarantines_under_duration_policy`
  and neighbours must keep passing; adjust only if the new behaviour
  makes an expectation genuinely wrong, and say so in the report.
- `hort-app` is a 100 %-coverage crate: every new branch needs a test.

## Acceptance

- The two remaining scenario asserts pass in a full compose suite run
  (operator-side; the isolated single-scenario form cannot reach the
  follower leg).
- `cargo test --workspace` green; fmt/clippy clean; audit/deny clean.
- The report states explicitly whether any existing test expectation
  changed and why.
